//= =====================
// Auth Actions
//= =====================
export const AUTH_USER = "auth_user",
  UNAUTH_USER = "unauth_user",
  AUTH_ERROR = "auth_error",
  FORGOT_PASSWORD_REQUEST = "forgot_password_request",
  RESET_PASSWORD_REQUEST = "reset_password_request",
  PROTECTED_TEST = "protected_test";

//= =====================
// User Profile Actions
//= =====================
export const FETCH_USER = "fetch_user",
  FETCH_USER_LIST = "fetch_user_list",
  FETCH_USER_SEARCH_LIST = "fetch_user_search_list",
  FETCH_MENTOR_LIST = "fetch_mentor_list",
  FETCH_JUDGE_LIST = "featch_judge_list",
  UPDATE_USER_PROFILE = "update_user_profile";
export const ERROR_RESPONSE = "error_response";

//= =====================
// Field data Actions
//= =====================
export const FETCH_FIELD_DATA = "fetch_field_data",
  CREATE_FIELD_DATA = "create_field_data",
  DELETE_FIELD_DATA = "delete_field_data",
  ADMIN_UPDATE_FIELD = "admin_set_column";

//= =====================
// Messaging Actions
//= =====================
export const FETCH_CONVERSATIONS = "fetch_conversations",
  SET_ON_MESSAGE = "set_on_message",
  SET_CHANNEL = "set_channel",
  FETCH_MESSAGES = "fetch_messages";

//= =====================
// Notification Actions
//= =====================
export const FETCH_NOTIFICATIONS = "fetch_notifications",
  READ_ONE_NOTIFICATION = "read_one_notification";

//= =====================
// Admin Actions
//= =====================
export const FETCH_ADMIN_PARTICIPANTS = "fetch_admin_participants",
  FETCH_REPORTS = "fetch_reports",
  UPDATE_ROLE = "update_role",
  FETCH_ADMIN_PARTICIPANT = "fetch_admin_participant";

//= =====================
// Faq Actions
//= =====================
export const FETCH_FAQ_LIST = "fetch_faq_list",
  CREATE_FAQ = "create_faq",
  DELETE_FAQ = "delete_faq",
  UPDATE_FAQ = "update_faq";
