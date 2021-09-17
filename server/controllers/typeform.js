const axios = require("axios");

const typeformAxios = axios.create({
  baseURL: process.env.TYPEFORM_BASE_URL,
  headers: { Authorization: `Bearer ${process.env.TYPEFORM_PERSONAL_TOKEN}` },
});

//= =======================================
// Typeform Routes
//= =======================================
exports.submitFilm = async (req, res, next) => {
  try {
    const { data } = await typeformAxios.get('/forms');

    const submitForm = data.items.find(
      (item) => item.title === "Submit Your Film"
    );
    return res.status(200).json({ item: submitForm });
  } catch (err) {
    res.status(500).send({ error: err });
    next(err)
  }
};
