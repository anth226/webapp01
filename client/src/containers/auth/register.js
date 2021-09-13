import React, { Component } from "react";
import { connect } from "react-redux";
import { Container } from "reactstrap";
import { Form, Input, message, Checkbox } from "antd";
import { LeftOutlined } from "@ant-design/icons";
import { registerUser } from "../../actions/auth";
import { Link } from "react-router-dom";
import { Header, Footer } from "../../components/template";

const SignupForm = ({ onSubmit }) => {
  const onFinish = (values) => {
    if (values.password.length < 8) {
      message.error("Password should be at least 8 characters in length");
      return;
    }
    if (values.password !== values.conf_password) {
      message.error("password confirmation doesn't match!");
      return;
    }
    delete values.conf_password;
    if (!values.agree_policy) return;
    onSubmit(values);
  };

  return (
    <Form name="register" className="login-form" onFinish={onFinish}>
      <React.Fragment>
        <span className="form-label">First name</span>
        <Form.Item
          name="first_name"
          rules={[
            {
              required: true,
              message: "Please input your first name!",
            },
          ]}
        >
          <Input size="large" placeholder="First Name" />
        </Form.Item>
        <span className="form-label">Last name</span>
        <Form.Item
          name="last_name"
          rules={[
            {
              required: true,
              message: "Please input your last name!",
            },
          ]}
        >
          <Input size="large" placeholder="Last Name" />
        </Form.Item>
      </React.Fragment>
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
        <Input size="large" type="email" placeholder="Email" />
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
        <Input size="large" type="password" placeholder="Password" />
      </Form.Item>
      <span className="form-label">Confirm password</span>
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
      <Form.Item name="agree_policy" valuePropName="checked">
        <Checkbox>
          <span className="checkbox-label w-form-label">
            I agree with the terms and policy
          </span>
        </Checkbox>
      </Form.Item>

      <div className="signup-btn">
        <button type="submit" className="hk_button">
          Continue
        </button>
      </div>
      <div className="mt-5 v-center">
        <LeftOutlined />
        <Link to="/">&nbsp; RETURN TO HOME</Link>
      </div>
    </Form>
  );
};

class Register extends Component {
  constructor(props) {
    super(props);

    this.state = {
      values: {},
      step: 0,
    };
  }

  onSubmit = (values) => {
    this.props.registerUser(values);
  };

  render() {
    return (
      <React.Fragment>
        <Header />
        <Container className="content">
          <div className="invite-box mt-5">
            <h3 className="summary-title text-center mb-4">
              <b>REGISTER</b>
            </h3>
            <SignupForm onSubmit={this.onSubmit} />
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
    message: state.auth.message,
    authenticated: state.auth.authenticated,
    fields: state.profile,
    location: state.location,
  };
}

export default connect(mapStateToProps, {
  registerUser,
})(Register);
