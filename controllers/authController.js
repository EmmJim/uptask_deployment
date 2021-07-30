const passport = require('passport');
const Usuarios = require('../models/Usuarios');
const { Op } = require("sequelize");
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const enviarEmail = require('../handlers/email');

// Autenticar el usuario
exports.autenticarUsuario = passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/iniciar-sesion',
    failureFlash: true,
    badRequestMessage: 'Ambos campos son obligatorios'
})

// Funcion para revisar si el usuario esta logueado o no
exports.usuarioAutenticado = (req, res, next) => {
    //Si el usuario esta autenticado, adelante
    if(req.isAuthenticated()){
        return next();
    }

    //Si no esta autenticado, redirigir al formulario
    return res.redirect('/iniciar-sesion');
}

//Funcion para cerrar sesion
exports.cerrarSesion = (req, res) => {
    req.session.destroy(() => {
        res.redirect('/iniciar-sesion'); // Al cerrar sesion nos lleva
    })
}

//Genera un token si el usuario es valido
exports.enviarToken = async(req, res, next) => {
    //Verificar que el usuario exista
    const {email} = req.body;
    const usuario = await Usuarios.findOne({
        where: {
            email
        }
    })

    //Si no existe el usuario
    if(!usuario){
        req.flash('error', 'No existe esa cuenta')
        res.redirect('/reestablecer');
    }

    //Usuario existe
    usuario.token = crypto.randomBytes(20).toString('hex');
    usuario.expiracion = Date.now() + 3600000;

    // Guardarlos en la BD
    await usuario.save();

    //Url de reset
    const resetUrl = `http://${req.headers.host}/reestablecer/${usuario.token}`;

    //Envia el correo con el token
    await enviarEmail.enviar({
        usuario,
        subject: 'Password Reset',
        resetUrl,
        archivo: 'reestablecer-password'
    })
    
    //Terminar la ejecucion
    req.flash('correcto', 'Se envió un mensaje a tu correo');
    res.redirect('/iniciar-sesion');
    

}

exports.validarToken = async (req, res, next) => {
    const usuario = await Usuarios.findOne({
        where: {
            token: req.params.token
        }
    })

    //Si no encuentra el usuario
    if(!usuario){
        req.flash('error', 'No válido');
        res.redirect('/reestablecer');
    }

    //Formulario para generar el password
    res.render('resetPassword', {
        nombrePagina: 'Reestablecer Contraseña'
    })

}

//Cambia el password por uno nuevo
exports.actualizarPassword = async (req, res, next) => {

    //Verifica el token valido pero tambien la fecha de expiracion
    const usuario = await Usuarios.findOne({
        where: {
            token: req.params.token,
            expiracion: {
                [Op.gte] : Date.now()
            }
        }
    })

    //Verificamos si el usuario existe
    if(!usuario){
        req.flash('error', ' No válido');
        res.redirect('/reestablecer');
    }

    //Hashear el nuevo password
    usuario.password = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));
    usuario.token = null;
    usuario.expiracion = null;

    // Guardamos el nuevo password
    await usuario.save();

    req.flash('correcto', 'Tu password se ha modificado correctamente');
    res.redirect('/iniciar-sesion');
    
}