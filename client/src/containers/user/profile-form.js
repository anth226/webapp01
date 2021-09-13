import React from "react";
import { Button, Form, Input, Select } from "antd";
import { Col, Row } from "reactstrap";
import { BigUpload } from "../../components/template";
import { countries } from "../../constants";
import { processLink, getFieldData } from "../../utils/helper";

const ProfileForm = ({
  onSubmit,
  profile,
  setAvatar,
  avatarURL,
  fieldData,
}) => {
  const positions = getFieldData(fieldData, "user_role");

  const onFinish = (values) => {
    values.photo = avatarURL;
    values.setting = profile.setting;
    values.facebook = processLink(values.facebook);
    values.linkedin = processLink(values.linkedin);
    values.twitter = processLink(values.twitter);
    values.web = processLink(values.web);
    onSubmit(values);
  };

  return (
    <Form
      name="org_register"
      onFinish={onFinish}
      initialValues={{ ...profile }}
    >
      <Row>
        <Col md={4} className="mb-4">
          <h4 className="mb-4">
            <b>
              {profile.first_name} {profile.last_name}
            </b>
          </h4>
          <BigUpload setAvatar={setAvatar} imageUrl={avatarURL} />
        </Col>
        <Col md={8}>
          <div className="account-form-box">
            <Row>
              <Col md={6} sm={12}>
                <span className="form-label">First name*</span>
                <Form.Item
                  name="first_name"
                  rules={[
                    {
                      required: true,
                      message: "Please input the first name!",
                    },
                  ]}
                >
                  <Input size="large" />
                </Form.Item>
              </Col>
              <Col md={6} sm={12}>
                <span className="form-label">Last name*</span>
                <Form.Item
                  name="last_name"
                  rules={[
                    {
                      required: true,
                      message: "Please input the last name!",
                    },
                  ]}
                >
                  <Input size="large" />
                </Form.Item>
              </Col>
            </Row>
            <Row>
              <Col md={6} sm={12}>
                <span className="form-label">Email</span>
                <Form.Item
                  name="email"
                  rules={[
                    {
                      required: true,
                      message: "Please input the email!",
                    },
                  ]}
                >
                  <Input type="email" size="large" />
                </Form.Item>
              </Col>
              <Col md={6} sm={12}>
                <span className="form-label">Phone</span>
                <Form.Item name="phone">
                  <Input size="large" />
                </Form.Item>
              </Col>
            </Row>
            <Row>
              <Col md={6} sm={12}>
                <span className="form-label">Country</span>
                <Form.Item name="country">
                  <Select size="large">
                    {countries.map((item) => (
                      <Select.Option key={item.name} value={item.name}>
                        {item.name}
                      </Select.Option>
                    ))}
                  </Select>
                </Form.Item>
              </Col>
              <Col md={6} sm={12}>
                <span className="form-label">Position</span>
                <Form.Item name="position">
                  <Select size="large">
                    {positions.map((item) => (
                      <Select.Option key={item._id} value={item.value}>
                        {item.value}
                      </Select.Option>
                    ))}
                  </Select>
                </Form.Item>
              </Col>
            </Row>
            <span className="form-label">Address</span>
            <Form.Item name="address">
              <Input size="large" />
            </Form.Item>
            <span className="form-label">
              What is ther best way to contact you?
            </span>
            <Form.Item name="contact">
              <Input size="large" />
            </Form.Item>
            <span className="form-label">Personal statement</span>
            <Form.Item name="personal_statement">
              <Input.TextArea rows={3} size="large" />
            </Form.Item>
          </div>

          <div className="account-form-box mt-4">
            <h5 className="mb-4">
              <b>Social information</b>
            </h5>
            <Row>
              <Col md={6} sm={12}>
                <span className="form-label">Twitter</span>
                <Form.Item name="twitter">
                  <Input size="large" />
                </Form.Item>
                <span className="form-label">LinkedIn</span>
                <Form.Item name="linkedin">
                  <Input size="large" />
                </Form.Item>
              </Col>
              <Col md={6} sm={12}>
                <span className="form-label">Facebook</span>
                <Form.Item name="facebook">
                  <Input size="large" />
                </Form.Item>
                <span className="form-label">Website</span>
                <Form.Item name="web">
                  <Input size="large" />
                </Form.Item>
              </Col>
            </Row>
          </div>
          <Button
            type="ghost"
            htmlType="submit"
            className="black-btn mt-4"
            style={{ float: "right" }}
          >
            Save
          </Button>
        </Col>
      </Row>
    </Form>
  );
};

export default ProfileForm;
