import React from "react";
import { Route, Switch } from "react-router-dom";
import { connect } from "react-redux";
import { BackTop } from "antd";

// Import miscellaneous routes and other requirements
import NotFoundPage from "./components/pages/not-found-page";

// Import static pages
import HomePage from "./containers/homepage";
import CinersPage from "./containers/ciners";

// Import authentication related pages
import Register from "./containers/auth/register";
import Login from "./containers/auth/login";
import Logout from "./containers/auth/logout";
import ForgotPassword from "./containers/auth/forgot_password";
import ResetPassword from "./containers/auth/reset_password";
import Resend from "./containers/auth/resend";
import ConfirmEmail from "./containers/auth/confirm-email";

// Import user related Pages
import UserDashboard from "./containers/user/dashboard";
import Participant from "./containers/user/user";
import Profile from "./containers/user/profilepage";

// Import admin related Pages
import AdminDashboard from "./containers/admin";

// Import chat related pages
import MessageBox from "./containers/message";

// Import notification pages
import Notification from "./containers/notification";

import Faq from "./containers/faq";

// Import higher order components
import RequireAuth from "./containers/auth/require_auth";
import { protectedTest } from "./actions/auth";
import { fetchConversations } from "./actions/message";
import { fetchNotifications } from "./actions/notification";
import { listFieldData } from "./actions/profile";

class Routes extends React.Component {
  componentDidMount = async () => {
    await this.props.protectedTest();
    this.props.fetchConversations();
    this.props.fetchNotifications();
    this.props.listFieldData();
  };

  render() {
    return (
      <div className="layout">
        <Switch>
          <Route exact path="/" component={HomePage} />
          <Route exact path="/ciners" component={CinersPage} />

          <Route path="/register" component={Register} />
          <Route path="/login" component={Login} />
          <Route path="/logout" component={Logout} />
          <Route path="/forgot-password/:mode" component={ForgotPassword} />
          <Route
            path="/reset-password/:mode/:resetToken"
            component={ResetPassword}
          />
          <Route path="/resend" component={Resend} />
          <Route path="/email-verify/:mode/:token" component={ConfirmEmail} />
          <Route path="/profile" component={RequireAuth(Profile)} />
          <Route path="/user-dashboard" component={UserDashboard} />

          <Route path="/participant/:id" component={Participant} />
          <Route path="/admin" component={RequireAuth(AdminDashboard)} />
          <Route path="/message" component={RequireAuth(MessageBox)} />
          <Route path="/notification" component={RequireAuth(Notification)} />

          <Route path="/faq" component={Faq} />
          <Route path="*" component={NotFoundPage} />
        </Switch>
        <BackTop />
      </div>
    );
  }
}

function mapStateToProps(state) {
  return { user: state.user };
}

export default connect(mapStateToProps, {
  protectedTest,
  fetchConversations,
  fetchNotifications,
  listFieldData,
})(Routes);
