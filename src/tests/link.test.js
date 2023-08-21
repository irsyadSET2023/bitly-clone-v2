import app from "../app";
import dbInit from "../database/init";
import postgressConnection from "../database/connection";
import { QueryTypes } from "sequelize";
import session from "supertest-session";
import supertest from "supertest";

const identifier = "irsyad";
const password = "irsyad1234";
const link =
  "https://discord.com/channels/1127827642909990994/1128184588443861032";
let authSession;
const link2 = "https://sequelize.org/docs/v6/core-concepts/raw-queries/";

describe("Test Link Api", function () {
  beforeEach(async function () {
    authSession = session(app);
    await dbInit();
    const dbQuery1 = await postgressConnection.query(
      `SELECT * FROM users WHERE user_name='${identifier}' OR email='${identifier}'`,
      { type: QueryTypes.SELECT }
    );
    const loginResponse = await authSession
      .post("/api/login")
      .send({ identifier, password });
    expect(loginResponse.status).toBe(200);
  });

  afterAll(async function () {
    postgressConnection.query(`DELETE FROM links  WHERE link='${link2}' `, {
      type: QueryTypes.DELETE,
    });
  });

  test("Created Link", async () => {
    const result = await authSession.post("/api/link").send({
      link: link,
    });
    expect(result.status).toBe(200);
    expect(result.body.message).toBe("Create new Link");
  });

  test("Updated Link", async () => {
    const dbQuery2 = await postgressConnection.query(
      `SELECT * FROM links WHERE link='${link}'`,
      { type: QueryTypes.SELECT }
    );
    const result = await authSession.put("/api/link").send({
      link: link2,
      id: dbQuery2[0].id,
    });
    expect(result.status).toBe(200);
    expect(result.body.message).toBe("Data Updated");
  });

  test("Logout Test", async () => {
    const logoutResponse = await authSession.post("/api/logout");
    expect(logoutResponse.status).toBe(200);
    expect(logoutResponse.body.message).toBe("Successfully logout");
  });
});

describe("Test Link Api test Unauthorized", function () {
  test("Created Link", async () => {
    const result = await supertest(app).post("/api/link").send({
      link: link,
    });
    expect(result.status).toBe(401);
    expect(result.body.message).toBe("Unauthorized");
  });

  test("Updated Link", async () => {
    const dbQuery2 = await postgressConnection.query(
      `SELECT * FROM links WHERE link='${link}'`,
      { type: QueryTypes.SELECT }
    );
    const result = await supertest(app).put("/api/link").send({
      //   link: link2,
      //   id: dbQuery2[0].id,
    });
    expect(result.status).toBe(401);
    expect(result.body.message).toBe("Unauthorized");
  });

  test("Logout Test", async () => {
    const logoutResponse = await supertest(app).post("/api/logout");
    expect(logoutResponse.status).toBe(401);
    expect(logoutResponse.body.message).toBe("Unauthorized");
  });
});
