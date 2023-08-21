import postgressConnection from "./connection";
import Link from "./model/Link";
import User from "./model/Users";

async function syncModels() {
  await postgressConnection.authenticate();
  await User.sync({ alter: true });
  await Link.sync({ alter: true });
}

async function dbInit() {
  try {
    console.debug("Connection to the database");
    await syncModels();
    console.debug("Connected to the database");
  } catch (error) {
    console.error("Failed to connect");
    process.exit(1);
  }
}

export default dbInit;
