import axios from "axios";
import cookie from "react-cookies";
import { API_URL, createNotification, errorMessage, Client } from "./index";
import {
  AUTH_USER,
  UNAUTH_USER,
  RESET_PASSWORD_REQUEST,
  FETCH_USER,
  FORGOT_PASSWORD_REQUEST,
} from "./types";
import history from "../history";
import { setMessageUserId } from "./message";
import { message } from "antd";

//= ===============================
// Authentication actions
//= ===============================
export function loginUser({ email, password }) {
  return async (dispatch) => {
    const client = Client();
    try {
      const response = await client.post(`${API_URL}/auth/login`, {
        email,
        password,
      });
      cookie.save("token", response.data.token, { path: "/" });
      const user = response.data.user;
      if (user) {
        cookie.save("user", user, { path: "/" });
        dispatch({ type: AUTH_USER });
        dispatch({ type: FETCH_USER, payload: user });
        setMessageUserId({ userId: user._id })(dispatch);
        history.push("/user-dashboard");
      }
    } catch (err) {
      createNotification("Login Failed", errorMessage(err));
    }
  };
}

export function registerUser(values) {
  return async (dispatch) => {
    let vrf = {};
    const client = Client();
    try {
      const response = await client.post(
        `${API_URL}/auth/user-register`,
        values
      );
      let user = response.data.user;
      vrf = {
        _id: user._id,
        name: `${user.profile.first_name} ${user.profile.last_name} `,
        email: user.email,
      };
      localStorage.setItem("vrf", JSON.stringify(vrf));
      history.push("/resend");
    } catch (err) {
      createNotification("Register Failed", errorMessage(err));
    }
  };
}

export function confirmEmail({ token, mode }) {
  return async (dispatch) => {
    try {
      const res = await axios.post(`${API_URL}/auth/verify`, { token, mode });
      const message = res.data.message;
      if (
        message &&
        (message.includes("verified successfully") ||
          message.includes("already been verified"))
      ) {
        localStorage.setItem("vrf", "");
      }
      return message;
    } catch (error) {
      createNotification("Confirm Email", errorMessage(error));
    }
  };
}

export function updateProfile({ profile }) {
  return function (dispatch) {
    const client = Client(true);
    client
      .post(`${API_URL}/user`, { profile })
      .then((response) => {
        dispatch({ type: FETCH_USER, payload: response.data.user });
      })
      .catch((error) => {
        createNotification("Update Profile", errorMessage(error));
      });
  };
}

export function logoutUser(error) {
  return function (dispatch) {
    dispatch({ type: UNAUTH_USER, payload: error || "" });
    cookie.remove("token", { path: "/" });
    cookie.remove("user", { path: "/" });
    history.push(`/login`);
  };
}

export function getForgotPasswordToken(email) {
  return async (dispatch) => {
    const client = Client();
    try {
      let res = await client.post(`${API_URL}/auth/forgot-password`, { email });
      dispatch({
        type: FORGOT_PASSWORD_REQUEST,
        payload: res.data.message,
      });
      history.push("/");
      message.success("Forgot password request has been sent successfully");
    } catch (err) {
      createNotification("Forgot Password", errorMessage(err));
    }
  };
}

export function resetPassword(token, password, conf_password) {
  return function (dispatch) {
    if (password !== conf_password) {
      createNotification("Reset Password", "password doesn't match");
      return;
    }
    axios
      .post(`${API_URL}/auth/reset-password/${token}`, { password })
      .then((response) => {
        dispatch({
          type: RESET_PASSWORD_REQUEST,
          payload: response.data.message,
        });
        history.push("/login");
      })
      .catch((error) => {
        createNotification("Reset Password", errorMessage(error));
      });
  };
}

export function resetPasswordSecurity(userid, password, conf_password) {
  return function (dispatch) {
    if (password !== conf_password) {
      createNotification("Reset Password", "password doesn't match");
      return;
    }
    axios
      .post(`${API_URL}/auth/reset-password-security`, { userid, password })
      .then((response) => {
        dispatch({
          type: RESET_PASSWORD_REQUEST,
          payload: response.data.message,
        });
        // Redirect to login page on successful password reset
        history.push("/login");
      })
      .catch((error) => {
        createNotification("Reset Password", errorMessage(error));
      });
  };
}

export function protectedTest() {
  return async (dispatch) => {
    try {
      let response = await axios.get(`${API_URL}/protected`, {
        headers: { Authorization: cookie.load("token") },
      });
      if (response.data.user) {
        dispatch({ type: AUTH_USER });
        dispatch({ type: FETCH_USER, payload: response.data.user });
        setMessageUserId({ userId: response.data.user._id })(dispatch);
      }
    } catch (error) {
      dispatch({ type: UNAUTH_USER, payload: "" });
    }
  };
}

export function getUser(userId) {
  return async (dispatch) => {
    const client = Client(true);
    try {
      let res = await client.get(`${API_URL}/user/${userId}`);
      return res.data.user;
    } catch (err) {
      createNotification("GET User", errorMessage(err));
    }
  };
}

export function resendVerification() {
  let vrf = localStorage.getItem("vrf");
  return (dispatch) => {
    if (!vrf) return;
    vrf = JSON.parse(vrf);
    axios.post(`${API_URL}/auth/resend`, vrf).catch((err) => {
      createNotification("Resend", errorMessage(err));
    });
  };
}
