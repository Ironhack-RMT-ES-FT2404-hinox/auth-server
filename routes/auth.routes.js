const User = require("../models/User.model");

const router = require("express").Router();
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

const { isTokenValid, isUserAdmin } = require("../middlewares/auth.middlewares.js")

// aqui van todas las rutas de autenticación

// POST "/api/auth/signup" => recibir data (email, username, password) del usuario y crearlo en la DB
router.post("/signup", async (req, res, next) => {

  console.log(req.body)
  const { email, username, password } = req.body


  // validaciones de servidor

  // 1. todos los campos deberian ser obligatorios
  if (!email || !username || !password) {
    res.status(400).json({errorMessage: "todos los campos son obligatorios"})
    return // detén la ejecución de la ruta
  }

  // 2. la contraseña deberia ser segura y fuerte
  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/gm
  if (passwordRegex.test(password) === false) {
    res.status(400).json({field: "password", errorMessage: "La contraseña no es suficientemente fuerte. Require más de 8 caracteres, al menos una minuscula, una mayuscula y algun otro caracter"})
    return // detén la ejecución de la ruta
  }

  // podriamos implementar más regex sobre otros campos, username, email.

  try {
    
    // 3. no deberia existir un usuario en la DB con ese mismo correo electronico
    const foundUser = await User.findOne({email: email})
    // console.log(foundUser)
    if (foundUser) {
      res.status(400).json({errorMessage: "Usuario ya registrado con ese correo electrónico"})
      return // detén la ejecución de la ruta
    }

    const salt = await bcrypt.genSalt(12)
    const hashPassword = await bcrypt.hash(password, salt)

    // creamos el documento de usuario en la DB
    await User.create({
      email: email,
      username: username,
      password: hashPassword // almacenamos en la DB la contraseña cifrada
    })

    res.sendStatus(201)
    
  } catch (error) {
    next(error)
  }

})

// POST "/api/auth/login" => recibe credenciales del usuario (email, password) y las valida. Crearemos y Enviaremos el Token.
router.post("/login", async (req, res, next) => {

  console.log(req.body)
  const { email, password } = req.body

  // 1. que los campos existan
  if (!email  || !password) {
    res.status(400).json({errorMessage: "todos los campos son obligatorios"})
    return // detén la ejecución de la ruta
  }

  try {
    
    // 2. el usuario exista
    const foundUser = await User.findOne( {email: email} )
    console.log(foundUser)
    if (!foundUser) {
      res.status(400).json({errorMessage: "Usuario no registrado"})
      return // detén la ejecución de la ruta
    }

    // 3. que la contraseña sea la correcta
    const isPasswordCorrect = await bcrypt.compare(password, foundUser.password)
    console.log(isPasswordCorrect)
    if (isPasswordCorrect === false) {
      res.status(400).json({errorMessage: "Contraseña no valida"})
      return // detén la ejecución de la ruta
    }

    
    // Ya hemos autenticado al usuario. Creamos el Token y lo enviamos.
    const payload = {
      _id: foundUser._id,
      email: foundUser.email,
      // cualquier informaciòn estatica del usuario deberia ir aqui
      role: foundUser.role
    }

    const authToken = jwt.sign(
      payload, // contenido del token
      process.env.TOKEN_SECRET, // la clave del servidor para cifrar TODOS los tokens
      { algorithm: "HS256", expiresIn: "7d" } // configuraciones del token
    )

    res.status(200).json({ authToken: authToken })

  } catch (error) {
    next(error)
  }

})

// GET "/api/auth/verify" => recibir el token y validarlo.
router.get("/verify", isTokenValid, (req, res, next) => {

  // que pasa si la ruta necesita saber quien es el usuario
  console.log(req.payload) //! ESTE ES EL USUARIO QUE ESTÁ HACIENDO ESTA LLAMADA
  //! ESTO AYUDA A SABER CUANDO CREAN DOCUMENTOS, QUIEN LO ESTA CREADO, O QUIEN PUEDE EDITARLO, QUIEN PUEDE BORRARLO.

  res.status(200).json({payload: req.payload}) // esta info la requiere el FE

})


// ejemplo de ruta que envia información solo para usuarios logeados (privado)
router.get("/private-route-example", isTokenValid, (req, res) => {

  // el isTokenValid es lo que haría que solo usuarios logeados puedes llegar
  // con el req.payload, el backend sabe quien es el usuario haciendo la llamada
  console.log(req.payload)
  res.json({data: "ejemplo información solo para usuarios logeados"})

})

// ejemplo de ruta solo para admins
router.get("/admin-route-example", isTokenValid, isUserAdmin, (req, res) => {

  res.json({data: "información super secreta de admin. Como conquistar el mundo"})

})

module.exports = router;