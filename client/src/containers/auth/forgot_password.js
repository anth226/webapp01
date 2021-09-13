import React, { Component } from "react";
import { connect } from "react-redux";
import { Container } from "reactstrap";
import { Form, Input } from "antd";
import { UserOutlined } from "@ant-design/icons";
import { getForgotPasswordToken } from "../../actions/auth";
import history from "../../history";
import { Link } from "react-router-dom";
import { Header, Footer } from "../../components/template";

const ForgotForm = ({ sendMail }) => {
  const onFinish = (values) => {
    sendMail(values.email);
  };

  return (
    <Form name="forgot" className="login-form" onFinish={onFinish}>
      <div className="auth-title mb-4">
        <div />
        <Link to="/">Back to Home</Link>
      </div>
      <Form.Item
        name="email"
        rules={[
          {
            required: true,
            message: "Please input your Email!",
          },
        ]}
      >
        <Input
          type="email"
          size="large"
          prefix={<UserOutlined className="site-form-item-icon" />}
          placeholder="Email"
        />
      </Form.Item>
      <button type="submit" className="covid-btn covid-success mt-5">
        Reset Password
      </button>
    </Form>
  );
};

class ForgotPassword extends Component {
  componentDidMount() {
    if (this.props.authenticated) {
      history.push("/user-dashboard");
      return;
    }
  }

  render() {
    return (
      <React.Fragment>
        <Header />
        <Container className="content">
          <div className="invite-box mt-5">
            <h3 className="summary-title text-center mb-4">
              <b>Forgot Password</b>
            </h3>
            <ForgotForm sendMail={this.props.getForgotPasswordToken} />
          </div>
        </Container>
        <Footer />
      </React.Fragment>
    );
  }
}

function mapStateToProps(state) {
  return {
    authenticated: state.auth.authenticated,
  };
}

export default connect(mapStateToProps, {
  getForgotPasswordToken,
})(ForgotPassword);
