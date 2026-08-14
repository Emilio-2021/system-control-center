import base64
import hashlib
import hmac
import os
import time

from fastapi import FastAPI, Depends, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db
import bcrypt 
from pydantic import BaseModel
from typing import List

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SESSION_SECRET = os.environ.get("SESSION_SECRET", "development-only-change-this-secret")
SESSION_TTL = 60 * 60 * 8


def _sign_session(username: str) -> str:
    issued = str(int(time.time()))
    payload = f"{username}|{issued}".encode()
    signature = hmac.new(SESSION_SECRET.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + b"|" + signature).decode()


def _read_session(token: str | None) -> str | None:
    if not token:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        username, issued, signature = raw.split(b"|", 2)
        payload = b"|".join((username, issued))
        expected = hmac.new(SESSION_SECRET.encode(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        if int(time.time()) - int(issued) > SESSION_TTL:
            return None
        return username.decode()
    except (ValueError, TypeError, OverflowError):
        return None
# -------------------------------------------------------------------------------
# GLOBAL REDIRECTION MIDDLEWARE FOR EXPIRED SESSIONS
# -------------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def auth_exception_handler(request: Request, exc: HTTPException):
    # If the app throws a 401 Unauthorized error anywhere, instantly redirect to login page
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return RedirectResponse(url="/?error=Please+login+first", status_code=303)
    
    # Return any other typical HTTP error messages normally (like 404 Not Found)
    return HTMLResponse(content=f"<h3>Error {exc.status_code}: {exc.detail}</h3>", status_code=exc.status_code)
# -------------------------------------------------------------------------------
# SECURITY ENFORCEMENT DEPENDENCY
# -------------------------------------------------------------------------------
def verify_session_cookie(request: Request, db: Session = Depends(get_db)) -> str:
    """
    Inspects the client's request cookies for an active session.
    If missing, triggers an unauthenticated HTTP exception.
    """
    username = _read_session(request.cookies.get("session_user"))
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session missing or expired"
        )
    if not db.execute(text("SELECT 1 FROM users WHERE username = :username"), {"username": username}).scalar():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists")
    return username
# -------------------------------------------------------------------------------
# LOGIN ROUTES (First page the user encounters)
# -------------------------------------------------------------------------------
@app.get('/', response_class=HTMLResponse)
def login_page(request: Request):
    # Check if they are already logged in; if so, skip login page
    if _read_session(request.cookies.get("session_user")):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})
# -------------------------------------------------------------------------------
@app.post('/login')
async def handle_login(
    request: Request, 
    username: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    # 1. Fetch user from your updated clean 'users' table
    sql = text("SELECT * FROM users WHERE username = :username")
    result = db.execute(sql, {"username": username}).fetchone()

    # 2. Check if the user exists
    if not result:
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Invalid username or password"}
        )
    
    # 3. Securely map the database fields
    user_data = result._mapping
    stored_hash = user_data.get('password_hash')
    
    # 4. Safely verify the plain-text form password against the stored bcrypt hash
    # (Bcrypt requires bytes, so we encode both strings to bytes before comparing)
    if not stored_hash or not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Invalid username or password"}
        )

    # 5. Log success action to audit_logs table
    audit_sql = text("INSERT INTO audit_logs (user_id, action) VALUES (:user_id, :action)")
    db.execute(audit_sql, {"user_id": result._mapping.get('id'), "action": "LOGIN_SUCCESS"})
    db.commit()

    # 6. Redirect to dashboard and set a secure session cookie
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="session_user",
        value=_sign_session(username),
        httponly=True,
        secure=os.environ.get("ENVIRONMENT") == "production",
        samesite="lax",
        max_age=SESSION_TTL,
    )
    return response
# -------------------------------------------------------------------------------
@app.get('/logout')
def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("session_user") # Destroy session cookie
    return response

# -------------------------------------------------------------------------------
# DASHBOARD ROUTE (Protected metrics page)
# -------------------------------------------------------------------------------
@app.get('/dashboard', response_class=HTMLResponse)
def view_dashboard(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    # Cleaned: Removed the tasks SQL query entirely
    entities_res = db.execute(text("SELECT entity_type, COUNT(*) as qty FROM entities GROUP BY entity_type")).fetchall()
    entities_data = [dict(row._mapping) for row in entities_res]
    audit_res = db.execute(text("SELECT COUNT(*) FROM audit_logs")).scalar()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "username": username,
        "entity_breakdown": entities_data,
        "total_logs": audit_res or 0
    })
# Keep your existing '/users-view', '/users/create', etc. below this point...
#-------------------------------------------------------------------------------
@app.get('/items')
def get_items(username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "Connected to Database"}
    except Exception as e:
        return {"status": "Database Connection Failed", "error": str(e)} 
#-------------------------------------------------------------------------------
def generate_html_grid(result) -> str:
    # 1. Fetch column headers automatically from the SQL result context
    columns = result.keys()
    
    html = "<style>table, th, td { border: 1px solid black; border-collapse: collapse; padding: 8px; }</style>"
    html += "<table>\n<thead>\n<tr>"
    for col in columns:
        html += f"<th>{col}</th>"
    html += "</tr>\n</thead>\n<tbody>\n"
    
    # 2. Fetch all database rows and loop through them dynamically
    rows = result.fetchall()
    for row in rows:
        html += "<tr>"
        for value in row:
            # Handle null/None database values gracefully
            val_str = str(value) if value is not None else ""
            html += f"<td>{val_str}</td>"
        html += "</tr>\n"
        
    html += "</tbody>\n</table>"
    return html
#-------------------------------------------------------------------------------        
@app.get('/users', response_class=HTMLResponse)
def view_users(username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    sql = text("SELECT id, username, email, created_at FROM users")
    result = db.execute(sql)
    
    if result.rowcount == 0:
        return """
        <html><body><h1>Database Record View</h1><p>No Data</p></body></html>
        """

    grid_html = generate_html_grid(result)
    
    return f"""
    <html>
    <body>
        <h1>Database Record View</h1>
        <p>Displaying data from DBGrid context...</p>
        {grid_html}
    </body>
    </html>
    """        
# -------------------------------------------------------------------------------
# SECURED USERS MATRIX VIEW
#-------------------------------------------------------------------------------   
@app.get('/users-view', response_class=HTMLResponse)
def view_users(request: Request, sort_by: str = "id", order: str = "ASC", username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    # 1. Whitelist inputs to protect against SQL Injection
    allowed_sort_columns = ["id", "username", "email", "created_at"]
    if sort_by not in allowed_sort_columns:
        sort_by = "id"
        
    # Enforce strict direction choices
    order = "DESC" if order.upper() == "DESC" else "ASC"

    # 2. Determine what the *next* click direction should be for each column
    # If the user clicks the current column, the next click should invert it.
    next_order = "DESC" if order == "ASC" else "ASC"

    # 3. Inject safe verified keywords into the ORDER BY clause
    sql = text(f"SELECT id, username, email, created_at FROM users ORDER BY {sort_by} {order}")
    result = db.execute(sql)
    
    grid_columns = ["id", "username", "email", "created_at"]
    raw_keys = result.keys()
    rows = [dict(zip(raw_keys, row)) for row in result.fetchall()]

    return templates.TemplateResponse("users.html", {
        "request": request,
        "columns": grid_columns,
        "rows": rows,
        "current_sort": sort_by,
        "current_order": order,       # Pass current state to template
        "next_order": next_order       # Pass calculated inverted state
    })
#-------------------------------------------------------------------------------    
# NEW ROUTE: Dynamically inserts form data into PostgreSQL
@app.post('/users/create')
async def create_user(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    # 1. Grab all fields submitted by the HTML form dynamically
    form_data = await request.form()
    form_dict = dict(form_data)
    allowed = {"username", "email", "password"}
    if set(form_dict) - allowed:
        return {"error": "Invalid user fields"}
    
    # 2. Extract plain text password, hash it, and swap keys
    if 'password' in form_dict and form_dict['password']:
        plain_password = form_dict.pop('password')
        # Hash the password and convert the resulting bytes back into a UTF-8 string
        salt = bcrypt.gensalt()
        hashed_bytes = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
        form_dict['password_hash'] = hashed_bytes.decode('utf-8')
    else:
        return {"error": "Failed to insert record", "details": "Password field is required"}

    # 3. Build a dynamic SQL string safely mapping fields to parameters
    columns = list(form_dict.keys())
    placeholders = ", ".join([f":{col}" for col in columns])
    column_str = ", ".join(columns)
    sql_query = text(f"INSERT INTO users ({column_str}) VALUES ({placeholders})")

    try:
        # Execute statement and commit it to save permanently
        db.execute(sql_query, form_dict)
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": "Failed to insert record", "details": str(e)}

    # 4. Refresh the page to show the newly added user automatically!
    return RedirectResponse(url="/users-view", status_code=303)
#-------------------------------------------------------------------------------    
@app.post('/users/update')
async def update_user(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    form_data = await request.form()
    form_dict = dict(form_data)
    if set(form_dict) - {"id", "username", "email", "password"} or "id" not in form_dict:
        return {"error": "Invalid user fields"}
    
    # 1. Pull out structural management IDs
    record_id = form_dict.pop('id')
    
    # 2. Check if a new password was provided in the edit modal form
    if 'password' in form_dict:
        new_password = form_dict.pop('password')
        if new_password.strip(): # If it's not an empty input box
            salt = bcrypt.gensalt()
            hashed_bytes = bcrypt.hashpw(new_password.encode('utf-8'), salt)
            form_dict['password_hash'] = hashed_bytes.decode('utf-8')

    # 3. Dynamically build standard SQL update structure
    if not form_dict:
        return {"error": "No changes submitted"}
    update_pairs = ", ".join([f"{col} = :{col}" for col in form_dict.keys()])
    sql_query = text(f"UPDATE users SET {update_pairs} WHERE id = :target_id")
    
    # 4. Bind variables and execute safely
    form_dict['target_id'] = record_id
    try:
        db.execute(sql_query, form_dict)
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": "Failed to update record", "details": str(e)}
        
    return RedirectResponse(url="/users-view", status_code=303)
#-------------------------------------------------------------------------------    
@app.post('/users/delete/{user_id}')
def delete_user(user_id: int, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    sql_query = text("DELETE FROM users WHERE id = :user_id")
    try:
        db.execute(sql_query, {"user_id": user_id})
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": "Failed to delete record", "details": str(e)}
    return RedirectResponse(url="/users-view", status_code=303)

# -------------------------------------------------------------------------------
# SECURED ENTITIES MATRIX VIEW
# -------------------------------------------------------------------------------
@app.get('/entities-view', response_class=HTMLResponse)
def view_entities(request: Request, sort_by: str = "id", order: str = "ASC", username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    # 1. Protect input arguments against injection
    allowed_sort_columns = ["id", "entity_type", "name", "email", "created_at"]
    if sort_by not in allowed_sort_columns:
        sort_by = "id"
        
    order = "DESC" if order.upper() == "DESC" else "ASC"
    next_order = "DESC" if order == "ASC" else "ASC"

    # 2. Query and clean columns array
    sql = text(f"SELECT id, entity_type, name, email, created_at FROM entities ORDER BY {sort_by} {order}")
    result = db.execute(sql)
    
    grid_columns = ["id", "entity_type", "name", "email", "created_at"]
    raw_keys = result.keys()
    rows = [dict(zip(raw_keys, row)) for row in result.fetchall()]

    return templates.TemplateResponse("entities.html", {
        "request": request,
        "columns": grid_columns,
        "rows": rows,
        "current_sort": sort_by,
        "current_order": order,
        "next_order": next_order
    })
#-------------------------------------------------------------------------------    
@app.post('/entities/create')
async def create_entity(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    form_data = await request.form()
    form_dict = dict(form_data)
    if set(form_dict) - {"entity_type", "name", "email"}:
        return {"error": "Invalid entity fields"}
    
    # Enforce uppercase types matching check constraint
    if 'entity_type' in form_dict:
        form_dict['entity_type'] = form_dict['entity_type'].upper()
    if form_dict.get('entity_type') not in {'PERSON', 'COMPANY'}:
        return {"error": "Invalid entity type"}

    columns = list(form_dict.keys())
    placeholders = ", ".join([f":{col}" for col in columns])
    column_str = ", ".join(columns)
    sql_query = text(f"INSERT INTO entities ({column_str}) VALUES ({placeholders})")

    try:
        db.execute(sql_query, form_dict)
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": "Failed to insert entity record", "details": str(e)}

    return RedirectResponse(url="/entities-view", status_code=303)
#-------------------------------------------------------------------------------    
@app.post('/entities/update')
async def update_entity(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    form_data = await request.form()
    form_dict = dict(form_data)
    if set(form_dict) - {"id", "entity_type", "name", "email"} or "id" not in form_dict:
        return {"error": "Invalid entity fields"}
    
    record_id = form_dict.pop('id')
    if 'entity_type' in form_dict:
        form_dict['entity_type'] = form_dict['entity_type'].upper()
    if form_dict.get('entity_type') not in {'PERSON', 'COMPANY'}:
        return {"error": "Invalid entity type"}

    if not form_dict:
        return {"error": "No changes submitted"}
    update_pairs = ", ".join([f"{col} = :{col}" for col in form_dict.keys()])
    sql_query = text(f"UPDATE entities SET {update_pairs} WHERE id = :target_id")
    
    form_dict['target_id'] = record_id
    try:
        db.execute(sql_query, form_dict)
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": "Failed to update entity record", "details": str(e)}
        
    return RedirectResponse(url="/entities-view", status_code=303)
#-------------------------------------------------------------------------------    
@app.post('/entities/delete/{entity_id}')
def delete_entity(entity_id: int, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    sql_query = text("DELETE FROM entities WHERE id = :entity_id")
    try:
        db.execute(sql_query, {"entity_id": entity_id})
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": "Failed to delete entity record", "details": str(e)}
    return RedirectResponse(url="/entities-view", status_code=303)
# -------------------------------------------------------------------------------
# PRODUCTS & INVENTORY CRUD SYSTEM
# -------------------------------------------------------------------------------
@app.get('/products-view', response_class=HTMLResponse)
def view_products(request: Request, sort_by: str = "id", order: str = "ASC", username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    allowed_sort_columns = ["id", "name", "sku", "price", "stock_quantity", "created_at"]
    if sort_by not in allowed_sort_columns:
        sort_by = "id"
        
    order = "DESC" if order.upper() == "DESC" else "ASC"
    next_order = "DESC" if order == "ASC" else "ASC"

    sql = text(f"SELECT id, name, sku, price, stock_quantity, created_at FROM products ORDER BY {sort_by} {order}")
    result = db.execute(sql)
    
    grid_columns = ["id", "name", "sku", "price", "stock_quantity", "created_at"]
    rows = [dict(zip(result.keys(), row)) for row in result.fetchall()]

    return templates.TemplateResponse("products.html", {
        "request": request,
        "columns": grid_columns,
        "rows": rows,
        "current_sort": sort_by,
        "current_order": order,
        "next_order": next_order
    })
# -------------------------------------------------------------------------------
@app.post('/products/create')
async def create_product(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    form_data = await request.form()
    form_dict = dict(form_data)
    if set(form_dict) - {"name", "sku", "price", "stock_quantity"}:
        return {"error": "Invalid product fields"}
    try:
        if float(form_dict["price"]) < 0 or int(form_dict["stock_quantity"]) < 0:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return {"error": "Price and stock must be valid non-negative numbers"}

    columns = list(form_dict.keys())
    placeholders = ", ".join([f":{col}" for col in columns])
    column_str = ", ".join(columns)
    sql_query = text(f"INSERT INTO products ({column_str}) VALUES ({placeholders})")

    try:
        db.execute(sql_query, form_dict)
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": "Failed to insert product", "details": str(e)}

    return RedirectResponse(url="/products-view", status_code=303)
# -------------------------------------------------------------------------------
@app.post('/products/update')
async def update_product(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    form_data = await request.form()
    form_dict = dict(form_data)
    if set(form_dict) - {"id", "name", "sku", "price", "stock_quantity"} or "id" not in form_dict:
        return {"error": "Invalid product fields"}
    try:
        if float(form_dict["price"]) < 0 or int(form_dict["stock_quantity"]) < 0:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return {"error": "Price and stock must be valid non-negative numbers"}
    
    record_id = form_dict.pop('id')
    if not form_dict:
        return {"error": "No changes submitted"}
    update_pairs = ", ".join([f"{col} = :{col}" for col in form_dict.keys()])
    sql_query = text(f"UPDATE products SET {update_pairs} WHERE id = :target_id")
    
    form_dict['target_id'] = record_id
    try:
        db.execute(sql_query, form_dict)
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": "Failed to update product", "details": str(e)}
        
    return RedirectResponse(url="/products-view", status_code=303)
# -------------------------------------------------------------------------------
@app.post('/products/delete/{product_id}')
def delete_product(product_id: int, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    try:
        db.execute(text("DELETE FROM products WHERE id = :product_id"), {"product_id": product_id})
        db.commit()
    except Exception as e:
        db.rollback()
        return {"error": "Failed to delete product", "details": str(e)}
    return RedirectResponse(url="/products-view", status_code=303)
# -------------------------------------------------------------------------------
# ORDERS & LINE ITEMS MATRIX VIEW
# -------------------------------------------------------------------------------
@app.get('/orders-view', response_class=HTMLResponse)
def view_orders(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    # 1. Fetch transaction headers along with their linked buyer Entity names
    orders_sql = text("""
        SELECT o.id as order_id, e.name as customer_name, o.status, o.created_at 
        FROM orders o
        JOIN entities e ON o.entity_id = e.id
        ORDER BY o.created_at DESC
    """)
    orders_res = db.execute(orders_sql).fetchall()
    
    # 2. Extract item rows grouped by individual order links
    items_sql = text("""
        SELECT oi.order_id, p.name as product_name, p.sku, oi.quantity, oi.unit_price, (oi.quantity * oi.unit_price) as row_total
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
    """)
    items_res = db.execute(items_sql).fetchall()
    
    # Group our data elements cleanly into list matrices for Jinja2
    orders_list = [dict(row._mapping) for row in orders_res]
    items_list = [dict(row._mapping) for row in items_res]

    return templates.TemplateResponse("orders.html", {
        "request": request,
        "orders": orders_list,
        "items": items_list
    })
# -------------------------------------------------------------------------------
# 1. Define a schema for parsing the incoming multi-item payload
class OrderItemPayload(BaseModel):
    product_id: int
    quantity: int
# -------------------------------------------------------------------------------
@app.get('/checkout', response_class=HTMLResponse)
def view_checkout_wizard(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    # FIXED: Explicitly force UPPERCASE string evaluation matching your data entries
    customers = db.execute(text("SELECT id, name, entity_type FROM entities WHERE entity_type IN ('PERSON', 'COMPANY') ORDER BY name ASC")).fetchall()
    products = db.execute(text("SELECT id, name, price, stock_quantity FROM products WHERE stock_quantity > 0 ORDER BY name ASC")).fetchall()
    
    return templates.TemplateResponse("checkout.html", {
        "request": request,
        "customers": [dict(c._mapping) for c in customers],
        "products": [dict(p._mapping) for p in products]
    })
# -------------------------------------------------------------------------------
@app.post('/checkout/create')
async def process_checkout_invoice(request: Request, username: str = Depends(verify_session_cookie), db: Session = Depends(get_db)):
    form_data = await request.form()
    
    # 2. Extract structural parameters out of the form payload
    try:
        entity_id = int(form_data.get("entity_id"))
    except (TypeError, ValueError):
        return {"error": "A valid customer is required"}
    
    # Extract lists of arrays generated dynamically by our JavaScript layout engine
    product_ids = form_data.getlist("product_id[]")
    quantities = form_data.getlist("quantity[]")

    if not product_ids or len(product_ids) == 0:
        return {"error": "Failed to process transaction", "details": "No products selected."}

    try:
        # 3. Open a secure transaction block context
        # Header Step: Create the parent Order record wrapper
        order_sql = text("""
            INSERT INTO orders (entity_id, status) 
            VALUES (:entity_id, 'COMPLETED') 
            RETURNING id
        """)
        order_id = db.execute(order_sql, {"entity_id": entity_id}).scalar()

        # 4. Loop through selected elements to generate Line Item records
        customer_exists = db.execute(
            text("SELECT 1 FROM entities WHERE id = :id AND entity_type IN ('PERSON', 'COMPANY')"),
            {"id": entity_id},
        ).scalar()
        if not customer_exists:
            raise ValueError("Selected entity is not a valid customer")

        for pid, qty in zip(product_ids, quantities):
            product_id = int(pid)
            quantity = int(qty)
            if quantity <= 0:
                raise ValueError("Quantity must be greater than zero")

            # Look up current product parameters (Price and Inventory)
            prod_data = db.execute(
                text("SELECT price, stock_quantity, name FROM products WHERE id = :id FOR UPDATE"), 
                {"id": product_id}
            ).fetchone()
            
            if not prod_data:
                raise Exception(f"Product ID {product_id} not found.")
                
            prod_mapped = prod_data._mapping
            unit_price = prod_mapped.get("price")
            current_stock = prod_mapped.get("stock_quantity")

            if current_stock < quantity:
                raise Exception(f"Insufficient stock for item '{prod_mapped.get('name')}'. Available: {current_stock}, Requested: {quantity}")

            # Step A: Insert line item matching historical locked-in unit prices
            item_sql = text("""
                INSERT INTO order_items (order_id, product_id, quantity, unit_price) 
                VALUES (:order_id, :product_id, :quantity, :unit_price)
            """)
            db.execute(item_sql, {
                "order_id": order_id,
                "product_id": product_id,
                "quantity": quantity,
                "unit_price": unit_price
            })

            # Step B: Deduct product inventory stock quantity counts immediately
            stock_update_sql = text("""
                UPDATE products 
                SET stock_quantity = stock_quantity - :qty 
                WHERE id = :id
            """)
            db.execute(stock_update_sql, {"qty": quantity, "id": product_id})

        # 5. Lock changes down permanently to Postgres disk storage engine
        db.commit()

    except Exception as e:
        db.rollback() # Safely discard all steps if a breakdown occurs to prevent broken entries
        return {"error": "Failed to create invoice record", "details": str(e)}

    return RedirectResponse(url="/orders-view", status_code=303)
