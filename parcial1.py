from fastapi import FastAPI, Depends, HTTPException, status, APIRouter
from pydantic import BaseModel 
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta

#implementar algoritmo de hasheo para encriptar contraseña
ALGORITHM = "HS256"
#duracion de autentiacion
ACCESS_TOKEN_DURATION = 2
#crear secret
SECRET= "123456789"

app = FastAPI()

#Autenticacion por contraseña
#Crear endpoint llamado "login"
oauth2 = OAuth2PasswordBearer(tokenUrl="login")

#crear contexto de encriptacion. 
#para eso se importa la libreria passlib
crypt = CryptContext(schemes="bcrypt")

class User(BaseModel):
    username:str
    full_name: str
    email:str
    phone: str
    disabled:bool

class UserDB(User):
    password:str

#directorio de los recursos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")
    
######## BASE DE DATOS
users_db = {
    "Yos":{
        "username": "Yos",
        "full_name": "Yosselin Pablo Ruiz",
        "email": "yosselin.pablo@alumno.buap.mx",
        "phone": "228 835 8188",
        "disabled": False,
        "password": "$2a$12$Sjt9pBEH1CN/XxCVGPrQhuC/BSuZFu4EJ6i6MGId7xby2FQMFEwdS" #1234
    },
    "Abraham":{
        "username": "Abraham",
        "full_name": "Abraham Coagtle Temiz",
        "email": "abraham.coagtle@alumno.buap.mx",
        "phone": "273 132 7748",
        "disabled": False,
        "password": "$2a$12$R7Wf0lfUSiQLAcdQTNvjyu8zLSWXg6m9hggF3sjgLGFY5gIgMBNQO"#hola
    },
    "Victor":{
        "username": "Victor",
        "full_name": "Victor Manuel Rosales",
        "email": "victor.rosalesz@alumno.buap.mx",
        "phone": "222 441 5653",
        "disabled": False,
        "password": "$2a$12$0v4E9esfh/rpFxyVUXc67.E9kDyAnBXkl3C82lac49yde9E8xs7.."#5678
    },
    "Kevin":{
        "username": "Kevin",
        "full_name": "Kevin Armas",
        "email": "kevin.armas@alumno.buap.mx",
        "phone": "614 199 8990",
        "disabled": False,
        "password": "$2a$12$2ezKODxwXHknFrUGrLDjmekgALiI.VN9LN2JRRYY7Xl1h969m8CFW"#4567
    },
    "JuanP":{
        "username": "JuanP",
        "full_name": "Juan Pablo Mendoza",
        "email": "juan.mendozaar@alumno.buap.mx",
        "phone": "228 177 6285",
        "disabled": False,
        "password": "$2a$12$7a8uyygaD6SiHCYuqLQ.2eDTKFvXgumN12TRdlE3g9NYz8WnkWoOy"#1111
    },
    "Luis":{
        "username": "Luis",
        "full_name": "Luis Delfino Castro",
        "email": "luis.castron@alumno.buap.mx",
        "phone": "811 050 2639",
        "disabled": False,
        "password": "$2a$12$2KjWHi3a82krm6D2sDs3eOIP2zDSZ7ymMWS46NK8TeoE.qODK5MrW"#2222
    },
    "Fany":{
        "username": "Fany",
        "full_name": "Estefania Rodríguez Martínez ",
        "email": "estefania.rodriguezma@alumno.buap.mx",
        "phone": "222 866 9227",
        "disabled": False,
        "password": "$2a$12$8NQRj43e6NZkVa1CKrr6Cu4ZW1D/nZh2YFhZC7AWuhPOcobssqAs6"#3333
    },
    "Pilar":{
        "username": "Pilar",
        "full_name": "Pilar Hernandez Zambrano",
        "email": "pilar.hernandezz@alumno.buap.mx",
        "phone": "222 322 3454",
        "disabled": False,
        "password": "$2a$12$JbZF.2cKmpEXG6D7k8Uew.O8pftQEMj8fqdkFFhKjX6xGjr3Ax9FC"#4444
    },
    "Vicente":{
        "username": "Vicente",
        "full_name": "Vicente Zavaleta Sanchez",
        "email": "vicente.zavaletas@alumno.buap.mx",
        "phone": "221 267 1849",
        "disabled": False,
        "password": "$2a$12$txOqUwMjjjLCM/71sD65.uJtcTAxpJEKRmK6LrJ/bWmb9mu1y/Cq6"#5555
    },
    "JosEd":{
        "username": "JosEd",
        "full_name": "José Eduardo Arrucha Álvarez ",
        "email": "jose.arruchaal@alumno.buap.mx",
        "phone": "221 331 7079",
        "disabled": False,
        "password": "$2a$12$0PRu12H7d6/RJXGHNxjoqeqVFxd8sJLO5M8hZEgvtKvhkCg9d/C9K"#6666
    }
}

#regresa el usuario completo de la base de datos (users_db)
def search_user_db(username:str):
    if username in users_db:
        return UserDB(**users_db[username]) #** devuelve todos los parámetros del usuario que coincida con username

#funcion para devolver el usuario a la solicitud del backend (con contraseña)
def search_user(username:str):
    if username in users_db:
        return User(**users_db[username])
    
#buscar al usuario
async def auth_user(token:str=Depends(oauth2)):
    try:
        username= jwt.decode(token, SECRET, algorithms=[ALGORITHM]).get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="El usuario no existe")
    
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales de autenticación inválidas")

    return search_user(username)

#verifica el usuario activo 
async def current_user(user:User = Depends(auth_user)):
    if user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuario inactivo")
    return user
        
####################################################################################3
#definir endpoint        
@app.post("/login/")
async def login(form:OAuth2PasswordRequestForm= Depends()):
    #buscar el username en la base de datos
    user_db = users_db.get(form.username)
    if not user_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario no existe")
    
    #obtener atributos incluyendo password del usuario que coincida con el username
    user = search_user_db(form.username)     
    
    #verificar contraseña correcta
    if not crypt.verify(form.password,user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Contraseña incorrecta")
    
    #crear expiracion a partir de la hora actual
    access_token_expiration=timedelta(minutes=ACCESS_TOKEN_DURATION)
    
    #timpoe de expiracion: hora actual + 1 min
    expire=datetime.utcnow()+access_token_expiration
    
    access_token={"sub": user.username,"exp": expire}
    return {"access_token": jwt.encode(access_token, SECRET,algorithm=ALGORITHM), "token_type":"bearer"}

@app.get("/users/me/")
async def me(user:User= Depends (current_user)): #Crea un user de tipo User que depende de la función (current_user)
    html_content = """
    <html>
        <head>
            <title>Some HTML in here</title>
            <link rel="stylesheet" href="../../static/styles.css">
        </head>
        <body>
            <div class="wrapper fadeInDown">
            <div id="formContent">
                <h2 class="active"> Hola de nuevo """ + user.username + """<h2>
                <div class="fadeIn first">
                    <img src="../../static/icons/""" + user.username + """.jpg" id="icon" alt="Icono de """ + user.username + """" />
                </div>
                <div>
                    <h2>Nombre:</h2>
                    <p> """ + user.full_name + """</p><br>
                    <h2>Correo:</h2>
                    <p> """ + user.email + """</p><br>
                    <h2>Telefono:</h2>
                    <p> """ + user.phone + """</p><br>
                </div>
                <div id="formFooter">
                    <a class="underlineHover" href="#"></a>
                </div>
            </div>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)

#http://127.0.0.1:8000/login/

#username:Abraham
#password:hola

#http://127.0.0.1:8000/users/me/

#app.mount("/static", StaticFiles(directory="static"), name="static")
# En el explorador colocamos el siguiente path para cargar recurso estático:
# http://127.0.0.1:8000/static/images/leopardo.jpg