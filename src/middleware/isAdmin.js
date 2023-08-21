import query from "../database";
import User from "../database/model/Users";

async function isAdmin(req, res, next) {
  //   const data = await query("SELECT is_admin FROM users WHERE id = $1", [
  //     req.user.id,
  //   ]);
  const data = await User.findOne({
    where: { id: req.user.id },
  });
  const user = data.rows[0];
  if (user.is_admin) {
    next();
  } else {
    res.status(403).json({ message: "Invalid admin request" });
  }
}

export default isAdmin;
