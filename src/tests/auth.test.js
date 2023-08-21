import supertest from "supertest";
import app from "../app";
import dbInit from "../database/init";
import postgressConnection from "../database/connection";
import { QueryTypes } from "sequelize";
import session from "supertest-session";

describe("test authentication controller", function () {
  beforeAll(async function () {
    await dbInit();
  });

  afterAll(async function () {
    postgressConnection.query("DELETE FROM users  WHERE user_name='adnan' ", {
      type: QueryTypes.DELETE,
    });
  });
  test("Login with the correct identifier and password", async function () {
    const result = await supertest(app)
      .post("/api/login")
      .send({ identifier: "irsyad", password: "irsyad1234" });
    expect(result.statusCode).toEqual(200);
    expect(result.body.message).toBe("Login successful");
  });

  test("Login with Empty identifier and password", async function () {
    const result = await supertest(app)
      .post("/api/login")
      .send({ identifier: "", password: "" });
    expect(result.statusCode).toEqual(403);
    expect(result.body.err.errors[0].msg).toBe("User Does Not Exist");
  });

  test("Register User with incorrect username that has number", async function () {
    const result = await supertest(app).post("/api/register").send({
      user_name: "adnan1243",
      password: "adnan1234",
      email: "adnan@gmail.com",
    });
    expect(result.statusCode).toEqual(403);
    expect(result.body.err.errors[0].msg).toBe("Must Be Alphabet Only");
  });

  test("Register User with incorrect email", async function () {
    const result = await supertest(app).post("/api/register").send({
      user_name: "adnan",
      password: "adnan1234",
      email: "adnan@gmail",
    });
    expect(result.statusCode).toEqual(403);
    expect(result.body.err.errors[0].msg).toBe("Must be email");
  });

  test("Register User with correct parameter", async function () {
    const result = await supertest(app).post("/api/register").send({
      user_name: "adnan",
      password: "adnan1234",
      email: "adnan@gmail.com",
    });
    expect(result.statusCode).toEqual(200);
    expect(result.body.message).toBe("Register");
  });
});

describe("test protected route", function () {
  const identifier = "irsyad";
  const password = "irsyad1234";
  let authSession;

  beforeEach(() => {
    authSession = session(app); // Use request.agent to maintain cookies
  });

  test("return 200 with message 'Protected Route' and user data, Check Logout", async () => {
    // Assuming your database query is correct and you're expecting only one result
    const dbQuery = await postgressConnection.query(
      `SELECT * FROM users WHERE user_name='${identifier}' OR email='${identifier}'`,
      { type: QueryTypes.SELECT }
    );

    const loginResponse = await authSession
      .post("/api/login")
      .send({ identifier, password });
    expect(loginResponse.status).toBe(200);

    const res = await authSession.get("/api/protected");
    expect(res.status).toBe(200);
    expect(res.body.message).toBe("Protected Route");
    expect(res.body.user).toBe(dbQuery[0].id); // Assuming id is the correct property

    const logoutResponse = await authSession.post("/api/logout");
    expect(logoutResponse.status).toBe(200);
    expect(logoutResponse.body.message).toBe("Successfully logout");
  });
});
