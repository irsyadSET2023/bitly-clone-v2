// import connectionDB from "./connection/index";
import postgressConnection from "../connection";
import { DataTypes } from "sequelize";
const User = postgressConnection.define(
  "User",
  {
    // Model attributes are defined here
    userName: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
  },
  {
    // Other model options go here
    timestamp: true,
    paranoid: true,
    underscored: true,
  }
);

export default User;
