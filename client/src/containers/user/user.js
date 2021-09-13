import React, { Component } from "react";
import { connect } from "react-redux";
import { Row, Col, Container } from "reactstrap";
import {
  Avatar,
  Skeleton,
  Modal,
  Input,
  Button,
  Dropdown,
  Menu,
  Popover,
} from "antd";
import {
  DownOutlined,
  FlagOutlined,
  UserDeleteOutlined,
} from "@ant-design/icons";
import { getUser } from "../../actions/auth";
import { startConversation, fetchOneConversation } from "../../actions/message";
import { blockUser, reportUser } from "../../actions/user";
import { Header, Footer } from "../../components/template";
import sampleUrl from "../../assets/images/user-avatar.png";
import history from "../../history";
class UserDashboard extends Component {
  constructor(props) {
    super(props);

    this.state = {
      user: {},
      loading: false,
      visible: false,
      chatText: "",
      reportText: "",
      reportShow: false,
    };
  }

  componentDidMount = async () => {
    this.setState({ loading: true });
    const userId = this.props.match.params.id;
    const { getUser } = this.props;

    const user = await getUser(userId);
    this.setState({
      user,
      loading: false,
    });
  };

  haveChat = () => {
    let conversations = this.props.message.conversations;
    for (let cv of conversations) {
      let filters =
        cv.participants.filter((pt) => pt._id === this.props.match.params.id) ||
        [];
      if (filters.length > 0 && cv.participants.length === 2) return true;
    }
    return false;
  };

  toggleModal = async () => {
    if (this.haveChat()) {
      await this.props.fetchOneConversation(this.props.match.params.id);
      history.push("/message");
      return;
    }
    this.setState({ visible: !this.state.visible });
  };

  onChangeChat = (e) => {
    this.setState({ chatText: e.target.value });
  };

  handleOk = () => {
    const { chatText } = this.state;
    if (!chatText) return;
    this.props.startConversation({
      recipient: this.props.match.params.id,
      composedMessage: chatText,
    });
    this.toggleModal();
  };

  mkReportMenu = (userId) => (
    <Menu>
      <Menu.Item key="2" onClick={() => this.props.blockUser(userId)}>
        <UserDeleteOutlined />
        <span>Block</span>
      </Menu.Item>
    </Menu>
  );

  isMyBlocker = () => {
    let blockers = this.props.user.blockers || [];
    for (let b of blockers) {
      if (b === this.props.match.params.id) return true;
    }
    return false;
  };

  onChangeReport = (e) => {
    this.setState({ reportText: e.target.value });
  };

  onChangeReportShow = (visible) => {
    this.setState({ reportShow: visible });
  };

  reportUser = () => {
    this.props.reportUser(this.props.match.params.id, this.state.reportText);
    this.setState({ reportShow: false, reportText: "" });
  };

  render = () => {
    const { user, visible, chatText } = this.state;
    return (
      <React.Fragment>
        <Header />
        <Container className="content">
          {user && (
            <div className="user-dashboard">{this.renderUserInfo(user)}</div>
          )}
          <Modal
            title={`Open Chat room with ${this.props.label.titleParticipant}`}
            visible={visible}
            onOk={this.handleOk}
            onCancel={this.toggleModal}
          >
            <Input.TextArea
              rows={2}
              onChange={this.onChangeChat}
              value={chatText}
              placeholder="Message"
            />
          </Modal>
        </Container>
        <Footer />
      </React.Fragment>
    );
  };

  renderUserInfo = (userData) => {
    const { user, isAdmin } = this.props;
    const userInfo = userData.profile;
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

          {user._id !== this.props.match.params.id && (
            <div className="flex" style={{ justifyContent: "space-between" }}>
              {!this.isMyBlocker() && (
                <Button type="primary" onClick={this.toggleModal}>
                  Send Message
                </Button>
              )}
              {isAdmin &&
                (userData.role === "Restrict" || userData.role === "Block") && (
                  <Button type="default" disabled>
                    {userData.role}
                  </Button>
                )}
              {isAdmin &&
                userData.role !== "Restrict" &&
                userData.role !== "Block" && (
                  <Dropdown
                    overlay={this.mkReportMenu(this.props.match.params.id)}
                    trigger={["click"]}
                  >
                    <Button>
                      <FlagOutlined /> <DownOutlined />
                    </Button>
                  </Dropdown>
                )}
              {!isAdmin && (
                <Popover
                  content={this.renderReportContent()}
                  title="Report User"
                  trigger="click"
                  visible={this.state.reportShow}
                  onVisibleChange={this.onChangeReportShow}
                >
                  <Button title="report">
                    <FlagOutlined />
                  </Button>
                </Popover>
              )}
            </div>
          )}
        </Col>
      </Row>
    );
  };

  renderReportContent = () => (
    <div>
      <Input.TextArea
        rows={2}
        onChange={this.onChangeReport}
        value={this.state.reportText}
      />
      <Button className="mt-2" type="primary" onClick={this.reportUser}>
        Submit
      </Button>
    </div>
  );

  renderSpin = () => {
    return (
      <Row>
        <Col className="center">
          <Skeleton active loading={this.state.loading} />
        </Col>
      </Row>
    );
  };
}
const mapStateToProps = (state) => {
  return {
    user: state.user.profile,
    isAdmin: state.user.isAdmin,
    message: state.message,
    fieldData: state.profile.fieldData,
  };
};

export default connect(mapStateToProps, {
  getUser,
  startConversation,
  blockUser,
  fetchOneConversation,
  reportUser,
})(UserDashboard);
