import { Op } from "sequelize";
import Link from "../../database/model/Link";

async function create(req, res) {
  const { link } = req.body;
  const owner = req.user.id;
  const slug = Math.random().toString(36).substring(2, 8);
  await Link.create({ slug: slug, link: link, owner: owner })
    .then(function (data) {
      console.log(data);
      res.status(200).json({ message: "Create new Link", data });
    })
    .catch(function (error) {
      console.log(error);
      res.status(500).json({ error });
    });
}

async function update(req, res) {
  const { slug, link } = req.body;
  await Link.update(
    { link },
    { where: { [Op.and]: [{ owner: req.user.id }, { slug: slug }] } }
  )
    .then(function (data) {
      res.status(200).json({ message: "Data Updated", data });
    })
    .catch(function (error) {
      res.status(500).json({ error });
    });
}

async function listAllbyUserId(req, res) {
  const userId = req.params.userId;

  await Link.findAndCountAll({
    attributes: ["slug", "link", "visit_counts"],
    order: [["created_at", "ASC"]],
    where: { owner: userId },
  })
    .then(function (data) {
      res
        .status(200)
        .json({ message: `${data.count} are found`, data: data.rows });
      return;
    })
    .catch(function (error) {
      res.status(500).json({ error });
      return;
    });
}

async function deleteLink(req, res) {
  await Link.destroy({
    where: {
      [Op.and]: [{ owner: req.user.id }, { slug: req.body.slug }],
    },
  })
    .then(function (data) {
      res.status(200).json({ message: "Link is deleted", data });
    })
    .catch(function (error) {
      res.status(500).json({ error });
    });
}

async function redirect(req, res) {
  const slug = req.params.slug;
  await Link.findOne({ where: { slug } })
    .then(function (data) {
      // console.log(data);
      if (data?.dataValues) {
        Link.update(
          { visit_counts: data.dataValues.visit_counts + 1 },
          { where: { slug } }
        )
          .then(function () {
            res.redirect(data.dataValues.link);
            return;
          })
          .catch(function (error) {
            res.status(500).json({ message: error });
            return;
          });
      } else {
        res.status(404).json({ message: "not found" });
        return;
      }
    })
    .catch(function (error) {
      res.status(500).json({ error });
    });
  // res.status(200).json({ message: "Redirect" });
}

const linkController = {
  create,
  update,
  listAllbyUserId,
  redirect,
  deleteLink,
};

export default linkController;
