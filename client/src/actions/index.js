import { notification } from "antd";
import axios from "axios";
import cookie from "react-cookies";

export const API_URL = process.env.REACT_APP_API_HOST;

export function createNotification(message, description) {
  notification.info({
    message,
    description,
    placement: "topRight",
  });
}

export function errorMessage(err) {
  if (!err.response) return err.message;
  if (err.response.data && err.response.data.error) {
    return err.response.data.error;
  }
  return err.message;
}

export const Client = (auth = false) => {
  const defaultOptions = {
    headers: auth
      ? {
          Authorization: cookie.load("token"),
        }
      : {},
  };

  return {
    get: (url, options = {}) =>
      axios.get(url, { ...defaultOptions, ...options }),
    post: (url, data, options = {}) =>
      axios.post(url, data, { ...defaultOptions, ...options }),
    put: (url, data, options = {}) =>
      axios.put(url, data, { ...defaultOptions, ...options }),
    delete: (url, options = {}) =>
      axios.delete(url, { ...defaultOptions, ...options }),
  };
};
