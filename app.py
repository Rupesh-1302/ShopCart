from chalice import Chalice, Response
from DatabaseTasks.main import Product, Cart, Session, User, engine
from hashlib import sha256

app = Chalice(app_name='checkout_cart')

local_session = Session(bind=engine)


@app.route('/hello')
def index():
    return {'hello': 'world'}


@app.route('/api/register', methods=['POST'])
def register():
    """ Register a new user """
    try:
        data = app.current_request.json_body
        user_name = data['user_name']
        full_name = data['full_name']
        password = data['password']

        if(len(password) < 8):
            return Response(
                body={
                    "Type": "Error",
                    "Message": "Password must be atleast 8 characters long"
                },
                status_code=400,
            )

        users = local_session.query(User).all()
        for user in users:
            if(user.user_name == user_name):
                return Response(
                    body={
                        "Type": "Error",
                        "Message": "User already exists"
                    },
                    status_code=400,
                )

        h = sha256()
        h.update(password.encode())
        hash = h.hexdigest()

        user_data = User(user_name=user_name,
                         full_name=full_name, password=hash)
        local_session.add(user_data)

        local_session.commit()

        return Response(
            body={
                "Type": "Success",
                "Message": "User registered successfully",
            },
            status_code=201,
        )

    except Exception as e:
        return Response(
            body={
                "Type": "Error",
                "Message": "Something went wrong, please try again.",
                "Error": str(e),
            },
            status_code=400,
        )


@app.route('/api/login', methods=['POST'])
def login():
    """ Login a user """
    try:
        data = app.current_request.json_body
        user_name = data['user_name']
        password = data['password']
        isUser = False

        users = local_session.query(User).all()
        for user in users:
            if(user.user_name == user_name):
                old_password = user.password
                isUser = True

        if not isUser:
            return Response(
                body={
                    "Type": "Error",
                    "Message": "User not registered",
                },
                status_code=400,
            )

        h = sha256()
        h.update(password.encode())
        hash = h.hexdigest()

        if(old_password != hash):
            return Response(
                body={
                    "Type": "Error",
                    "Message": "Password is incorrect",
                },
                status_code=400,
            )

        return Response(
            body={
                "Type": "Success",
                "Message": "User logged in successfully",
            },
            status_code=200,
        )

    except Exception as e:
        return Response(
            body={
                "Type": "Error",
                "Message": "Something went wrong, please try again.",
                "Error": str(e),
            },
            status_code=400,
        )


@app.route('/api/cart', methods=['POST', 'DELETE'], cors=True)
def handle_cart():
    request = app.current_request
    data = request.json_body
    user_id = data["userId"] if "userId" in data else None
    product_id = data["productId"] if "productId" in data else None
    quantity = 1
    if 'quantity' in data:
        quantity = data["quantity"]
    if not user_id or not product_id:
        return Response(status_code=403, body={"message": "Invalid Request"})

    if request.method == 'POST':
        try:
            newCartItem = Cart(
                userId=user_id, productId=product_id, quantity=quantity)
            local_session.add(newCartItem)
            local_session.commit()
            return Response(status_code=200, body={"message": "Item added to cart successfully"})
        except Exception as e:
            print(e)
            return Response(status_code=400, body={"message": "Something went Wrong"})
    else:
        try:
            cartItem = local_session.query(Cart).filter(
                Cart.userId == user_id).filter(Cart.productId == product_id).first()
            local_session.delete(cartItem)
            local_session.commit()
            return Response(status_code=200, body={"message": "Item deleted from cart successfully"})
        except Exception as e:
            print(e)
            return Response(status_code=400, body={"message": "Something went Wrong"})
