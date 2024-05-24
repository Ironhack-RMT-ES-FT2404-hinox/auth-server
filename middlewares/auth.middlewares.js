const jwt = require("jsonwebtoken")

function isTokenValid (req, res, next) {

  try {
    
    // console.log(req.headers.authorization)
    const token = req.headers.authorization.split(" ")[1] // coje el token del string
    // console.log(token)

    // validar el token
    const payload = jwt.verify(token, process.env.TOKEN_SECRET)
    // 1. validar el token
    // 2. devolverme el payload
    // console.log(payload)

    req.payload = payload // pasar el payload del middleware a la ruta
    
    // si el token es valido permitirle acceder a la ruta
    next()
    
  } catch (error) {
    // si el token no es valido, enviar un error
    res.status(401).json({errorMessage: "Token no valido o no existe"})
    //1. ocurre si el token no existe
    //2. ocurre si el token fue manipulado (alguien se hacer pasar por otra persona)
    //3. ocurre si el token ya no es valido
  }

}

module.exports = {
  isTokenValid
}