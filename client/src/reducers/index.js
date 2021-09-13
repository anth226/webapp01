import { combineReducers } from "redux";
import authReducer from "./auth";
import userReducer from "./user";
import profileReducer from "./profile";
import messageReducer from "./message";
import notificationReducer from "./notification";
import adminReducer from "./admin";
import faqReducer from "./faq";

const rootReducer = combineReducers({
  auth: authReducer,
  user: userReducer,
  profile: profileReducer,
  message: messageReducer,
  notification: notificationReducer,
  admin: adminReducer,
  faq: faqReducer,
});

export default rootReducer;
