import React, { Component } from "react";
import { Container } from "reactstrap";
import { connect } from "react-redux";
import { resetPassword, resetPasswordSecurity } from "../../actions/auth";
import { Header, Footer } from "../../components/template";
import { Form, Input } from "antd";
import { LeftOutlined } from "@ant-design/icons";
import { Link } from "react-router-dom";

const ResetPasswordForm = ({
  resetPassword,
  resetPasswordSecurity,
  message,
  token,
}) => {
  const onFinish = (values) => {
    if (token && token.includes("security")) {
      let userid = token.replace("security", "");
      resetPasswordSecurity(userid, values.password, values.conf_password);
    } else {
      resetPassword(token, values.password, values.conf_password);
    }
  };

  return (
    <Form name="reset" className="login-form" onFinish={onFinish}>
      <div className="auth-title mb-4">
        <div />
        <Link to="/">Back to Home</Link>
      </div>

      <Form.Item
        name="password"
        rules={[
          {
            required: true,
            message: "Please input your Password!",
          },
        ]}
      >
        <Input size="large" type="password" placeholder="Password" />
      </Form.Item>
      <Form.Item
        name="conf_password"
        rules={[
          {
            required: true,
            message: "Please confirm your Password!",
          },
        ]}
      >
        <Input size="large" type="password" placeholder="Confirm Password" />
      </Form.Item>
      {message && <p>{message}</p>}
      <div className="signup-btn">
        <button type="submit" className="hk_button">
          Reset Password
        </button>
      </div>
      <div className="mt-5 v-center">
        <LeftOutlined />
        <Link to="/">&nbsp; RETURN TO HOME</Link>
      </div>
    </Form>
  );
};

class ResetPassword extends Component {
  componentDidMount() {
    if (this.props.authenticated) {
      this.context.router.push("/");
    }
  }

  render() {
    const { resetPassword, resetPasswordSecurity, message, match } = this.props;
    return (
      <React.Fragment>
        <Header />
        <Container className="content">
          <div className="invite-box mt-5">
            <h3 className="summary-title text-center mb-4">
              <b>Reset Password</b>
            </h3>
            <ResetPasswordForm
              resetPassword={resetPassword}
              resetPasswordSecurity={resetPasswordSecurity}
              message={message}
              token={match.params.resetToken}
            />
          </div>
        </Container>
        <Footer />
      </React.Fragment>
    );
  }
}

function mapStateToProps(state) {
  return { errorMessage: state.auth.error, message: state.auth.resetMessage };
}

export default connect(mapStateToProps, {
  resetPassword,
  resetPasswordSecurity,
})(ResetPassword);
