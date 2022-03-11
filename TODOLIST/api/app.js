const express = require('express');
const app = express();
const mysql = require('mysql');

const { mysql } = require('./db/CreateDB');

const bodyParser = require('body-parser');



const jwt = require('jsonwebtoken');



app.use(bodyParser.json());


app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token, _id");

    res.header(
        'Access-Control-Expose-Headers',
        'x-access-token, x-refresh-token'
    );

    next();
});



let authenticate = (req, res, next) => {
    let token = req.header('x-access-token');

    jwt.verify(token, User.getJWTSecret(), (err, decoded) => {
        if (err) {

            res.status(401).send(err);
        } else {
            
            req.user_id = decoded._id;
            next();
        }
    });
}


let verifySession = (req, res, next) => {

    let refreshToken = req.header('x-refresh-token');


    let _id = req.header('_id');

    User.findByIdAndToken(_id, refreshToken).then((user) => {
        if (!user) {

            return Promise.reject({
                'error': 'User not found. Make sure that the refresh token and user id are correct'
            });
        }



        req.user_id = user._id;
        req.userObject = user;
        req.refreshToken = refreshToken;

        let isSessionValid = false;

        user.sessions.forEach((session) => {
            if (session.token === refreshToken) {

                if (User.hasRefreshTokenExpired(session.expiresAt) === false) {

                    isSessionValid = true;
                }
            }
        });

        if (isSessionValid) {
            
            next();
        } else {
            return Promise.reject({
                'error': 'Refresh token has expired or the session is invalid'
            })
        }

    }).catch((e) => {
        res.status(401).send(e);
    })
}

















app.post('/users', (req, res) => {


    let body = req.body;
    let newUser = new User(body);

    newUser.save().then(() => {
        return newUser.createSession();
    }).then((refreshToken) => {


        return newUser.generateAccessAuthToken().then((accessToken) => {

            return { accessToken, refreshToken }
        });
    }).then((authTokens) => {
      
        res
            .header('x-refresh-token', authTokens.refreshToken)
            .header('x-access-token', authTokens.accessToken)
            .send(newUser);
    }).catch((e) => {
        res.status(400).send(e);
    })
})



app.post('/users/login', (req, res) => {
    let email = req.body.email;
    let password = req.body.password;

    User.findByCredentials(email, password).then((user) => {
        return user.createSession().then((refreshToken) => {
        

            return user.generateAccessAuthToken().then((accessToken) => {
                
                return { accessToken, refreshToken }
            });
        }).then((authTokens) => {
           
            res
                .header('x-refresh-token', authTokens.refreshToken)
                .header('x-access-token', authTokens.accessToken)
                .send(user);
        })
    }).catch((e) => {
        res.status(400).send(e);
    });
})






app.listen(3000, () => {
    console.log("Server is listening on port 3000");
})