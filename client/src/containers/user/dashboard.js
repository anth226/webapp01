import React, { Component } from "react";
import { connect } from "react-redux";
import { Row, Col, Container } from "reactstrap";
import { Avatar, Skeleton } from "antd";
import { Header, Footer } from "../../components/template";
import sampleUrl from "../../assets/images/user-avatar.png";

class UserDashboard extends Component {
  render = () => {
    const { user } = this.props;
    const userInfo = user.profile;

    return (
      <React.Fragment>
        <Header />
        <Container className="content">
          <div className="user-dashboard">{this.renderUserInfo(userInfo)}</div>
        </Container>
        <Footer />
      </React.Fragment>
    );
  };

  renderUserInfo = (userInfo) => {
    if (!userInfo) {
      return this.renderSpin();
    }
    return (
      <Row>
        <Col xl={4} md={5} className="mb-3">
          <div className="user-card">
            <Avatar src={userInfo.photo || sampleUrl} size={200} />
          </div>
        </Col>
        <Col xl={8} md={7}>
          <h3>
            {userInfo.first_name} {userInfo.last_name}
          </h3>
          <p className="mt-4">
            <b style={{ fontSize: "13px" }}>{userInfo.country}</b>
          </p>
          <div
            className="sun-editor-editable mt-4"
            dangerouslySetInnerHTML={{ __html: userInfo.personal_statement }}
          />
          <p>
            <b>Contact:&nbsp;&nbsp;</b>
            <span>{userInfo.contact}</span>
          </p>
        </Col>
      </Row>
    );
  };

  renderSpin = () => {
    return (
      <Row>
        <Col className="center">
          <Skeleton active loading={true} />
        </Col>
      </Row>
    );
  };
}
const mapStateToProps = (state) => {
  return {
    user: state.user.profile,
    fieldData: state.profile.fieldData,
  };
};

export default connect(mapStateToProps, {})(UserDashboard);
