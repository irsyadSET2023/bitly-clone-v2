import User from "../../database/model/Users";
import bcrypt from "bcryptjs";
import { validationResult } from "express-validator";
import { Op } from "sequelize";
import jwt from "jsonwebtoken";
import config from "../../config";

async function register(req, res) {
  const { user_name, email, password } = req.body;
  let saltRounds = 10;
  const hashedPassword = bcrypt.hashSync(password, saltRounds);

  await User.create({
    userName: user_name,
    email: email,
    password: hashedPassword,
  })
    .then(function (data) {
      console.log(data);
      return res.status(200).json({
        message: "Register",
        data: { id: data.id, username: data.userName, email: data.email },
      });
    })
    .catch(function (error) {
      console.log(error);
      return res.status(500).json({ error });
    });
}

async function login(req, res) {
  const { identifier, password } = req.body;
  const data = await User.findOne({
    where: {
      [Op.or]: [{ userName: identifier }, { email: identifier }],
    },
  });

  const user = data.dataValues;
  console.log(user);

  const generatAccessToken = (userData) => {
    return jwt.sign(userData, config.jwtSecretToken, { expiresIn: "4800s" });
  };

  bcrypt.compare(password, user.password, (error, bcryptRes) => {
    if (bcryptRes) {
      console.log("User Id", user.id);
      req.token = user.id;
      console.log("Token", req.token);

      const token = generatAccessToken({
        id: user.id,
        username: user.userName,
        email: user.email,
      });
      const serverRes = {
        message: "Login successful",
        data: { id: user.id, username: user.userName, email: user.email },
        jwt: token,
      };
      res.status(200).json(serverRes);
    } else {
      const serverRes = {
        message: "Login Unsuccesful",
        error: "Invalid credential",
        data: error,
      };
      res.status(401).json(serverRes);
    }
  });
}

function logout(req, res) {
  // const session = req.session.destroy();
  // console.log(session);
  res.status(200).json({ message: "Successfully logout" });
}

const authController = { register, login, logout };

export default authController;
