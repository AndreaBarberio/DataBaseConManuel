const User = require("../database/models/user.model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

module.exports.signup = async (req, res) => {
    let { email, password } = req.body;

    try {
        if (password.length < 8) {
            throw new Error("La password deve essere di almeno 8 caratteri")
        }
        //controllo se esiste un utente con la mail passata nella post 
        let user = await User.findOne({ email: email });
        if (user) {
            //se esiste 
            throw new Error("Esiste già un utente con questa email")
        } else {
            password = await bcrypt.hash(password, 12);
            let userData = new User({ email: email, password: password });
            // salvo utente su db 
            await userData.save();
            // rispondo al client 
            res.send({ status: 200, message: "Complimenti, ti sei iscritto correttamente :D", body: {} })
        }
    }
    // catturo eventuali errori 
    catch (error) {
        //qualunque eccezione risponde al client con il messaggio lanciato 
        res.send({ status: 400, message: error.message, body: {} });
    }
}

module.exports.login = async (req, res) => {
    let { email, password } = req.body;

    try {
        let user = await User.findOne({ email: email });
        //verifico che esista un utente con la mail usata nel frontend, 
        if (!user) {
            //se non esiste lanciamo l'errore
            throw new Error("Mi dispiace, non esiste alcun utente con questa mail")
        } else {

            //se esiste controllo che la password sia corretta
            let isCorrect = await bcrypt.compare(password, user.password);



            if (!isCorrect) {
                throw new Error("La password inserita non è corretta")
            } else {
                const token = await jwt.sign(
                    { email: user.email },

                    process.env.SECRET_KEY,
                    { expiresIn: '1d' })

                res.send({ status: 200, message: 'Login effettuato correttamente', body: token, })
            }
        }
    } catch (error) {
        res.send({ status: 400, message: error.message, body: {} })
    }
}

module.exports.delete = async (req, res) => {
    let { email, password } = req.body;

    try {
        let user = await User.findOne({ email: email });
        //verifico che esista un utente con la mail usata nel frontend, 
        if (!user) {
            //se non esiste lanciamo l'errore
            throw new Error("Mi dispiace, non esiste alcun utente con questa mail")
        } else {

            //se esiste controllo che la password sia corretta
            let isCorrect = await bcrypt.compare(password, user.password);



            if (!isCorrect) {
                throw new Error("La password inserita non è corretta")
            } else {
                user.remove()

                res.send({ status: 200, message: 'Profilo eliminato correttamente dal database' })
            }

        }

    } catch (error) {
        res.send({ status: 400, message: error.message, body: {} })
    }
}
