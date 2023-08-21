// import connectionDB from "./connection/index";
import postgressConnection from "../connection";
import User from "./Users";
import { DataTypes } from "sequelize";
const Link = postgressConnection.define(
  "Link",
  {
    // Model attributes are defined here
    slug: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    link: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: false,
    },
    visit_counts: {
      type: DataTypes.INTEGER,
      allowNull: false,
      unique: false,
      defaultValue: 0,
    },
  },
  {
    // Other model options go here
    timestamp: true,
    paranoid: true,
    underscored: true,
  }
);

Link.belongsTo(User, {
  foreignKey: "owner",
});

export default Link;
