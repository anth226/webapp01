import React, { Component } from "react";
import { connect } from "react-redux";
import { Container } from "reactstrap";
import { Form, Input, Checkbox } from "antd";
import { UserOutlined, LockOutlined, LeftOutlined } from "@ant-design/icons";
import { Link } from "react-router-dom";
import { loginUser, resendVerification } from "../../actions/auth";
import history from "../../history";
import { Header, Footer } from "../../components/template";

const LoginForm = ({ onSubmit }) => {
  const onFinish = (values) => {
    onSubmit(values);
  };

  return (
    <Form
      name="login"
      className="login-form"
      initialValues={{ remember: true }}
      onFinish={onFinish}
    >
      <span className="form-label">Email</span>
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
          size="large"
          type="email"
          prefix={<UserOutlined className="site-form-item-icon" />}
          placeholder="Email"
        />
      </Form.Item>
      <span className="form-label">Password</span>
      <Form.Item
        name="password"
        rules={[
          {
            required: true,
            message: "Please input your Password!",
          },
        ]}
      >
        <Input
          size="large"
          prefix={<LockOutlined className="site-form-item-icon" />}
          type="password"
          placeholder="Password"
        />
      </Form.Item>
      {/* {error && error.includes("not verified") && (
        <Link className="login-verify" to="#" onClick={resend}>
          Resend Verification Email<br/><br/>
        </Link>
      )} */}
      <button type="submit" className="hk_button">
        Log in
      </button>
      <br />
      <Form.Item>
        <Form.Item name="remember" noStyle>
          <div className="mt-2 login-remember">
            <Checkbox>Remember me</Checkbox>
          </div>
        </Form.Item>
      </Form.Item>
      <div className="mt-3">
        <Link to="/forgot-password/user">Forgot password</Link>
      </div>
      <div className="mt-5 v-center">
        <LeftOutlined />
        <Link to="/">&nbsp; RETURN TO HOME</Link>
      </div>
    </Form>
  );
};

class Login extends Component {
  componentDidMount() {
    if (this.props.authenticated && this.props.loginMode === 0) {
      history.push("/user-dashboard");
      return;
    }
  }

  render() {
    const { loginUser, resendVerification } = this.props;
    return (
      <React.Fragment>
        <Header />
        <Container className="content">
          <div className="invite-box mt-5">
            <h3 className="summary-title text-center mb-4">
              <b>LOG IN</b>
            </h3>
            <LoginForm onSubmit={loginUser} resend={resendVerification} />
          </div>
        </Container>
        <Footer />
      </React.Fragment>
    );
  }
}

function mapStateToProps(state) {
  return {
    errorMessage: state.auth.error,
    authenticated: state.auth.authenticated,
    loginMode: state.auth.loginMode,
  };
}

export default connect(mapStateToProps, { loginUser, resendVerification })(
  Login
);
