import React, { Component } from "react";
import { connect } from "react-redux";
import { Layout, Menu, Breadcrumb } from "antd";
import { UserOutlined } from "@ant-design/icons";
import { Header } from "../../components/template";
// import history from "../../history";
import UserAll from "./user/all";
import Message from "./user/message";
import Reports from "./user/report";
import Verify from "./user/unverified";
import Faq from "./faq";

const { Content, Sider } = Layout;
const { SubMenu } = Menu;

class AdminDashboard extends Component {
  state = {
    collapsed: false,
    pageTitle: "",
    submenu: "",
  };

  onCollapse = (collapsed) => {
    this.setState({ collapsed });
  };

  // componentDidMount() {
  //   if (!this.props.isAdmin) {
  //     history.push("/user-dashboard");
  //     return;
  //   }
  // }

  switchPage = (submenu, pageTitle) => {
    this.setState({ submenu, pageTitle });
  };

  render() {
    const { pageTitle, submenu } = this.state;

    return (
      <React.Fragment>
        <Header />
        <Layout className="message-box">
          <Sider
            collapsible
            collapsed={this.state.collapsed}
            onCollapse={this.onCollapse}
          >
            <Menu theme="dark" defaultSelectedKeys={["1"]} mode="inline">
              <SubMenu
                key="sub1"
                title={
                  <span>
                    <UserOutlined />
                    <span>Users</span>
                  </span>
                }
              >
                <Menu.Item
                  key="pt-all"
                  onClick={() => this.switchPage("Participant", "All")}
                >
                  All
                </Menu.Item>
                <Menu.Item
                  key="pt-msg"
                  onClick={() => this.switchPage("Participant", "Message")}
                >
                  Message
                </Menu.Item>
                <Menu.Item
                  key="pt-rpt"
                  onClick={() => this.switchPage("Participant", "Report")}
                >
                  Report
                </Menu.Item>
                <Menu.Item
                  key="pt-vrf"
                  onClick={() => this.switchPage("Participant", "Verify")}
                >
                  Unverified
                </Menu.Item>
              </SubMenu>
            </Menu>
          </Sider>
          <Layout className="site-layout">
            <Content style={{ margin: "0 16px" }}>
              <Breadcrumb style={{ margin: "16px 0" }}>
                <Breadcrumb.Item>{submenu}</Breadcrumb.Item>
                <Breadcrumb.Item>{pageTitle}</Breadcrumb.Item>
              </Breadcrumb>
              <div className="admin-main">{this.renderPage()}</div>
            </Content>
          </Layout>
        </Layout>
      </React.Fragment>
    );
  }

  renderPage = () => {
    const { pageTitle, submenu } = this.state;
    let pageName = `${submenu} ${pageTitle}`;
    switch (pageName) {
      case "Participant All":
        return <UserAll />;
      case "Participant Message":
        return <Message />;
      case "Participant Report":
        return <Reports />;
      case "Participant Verify":
        return <Verify />;
      case "Setting Faq":
        return <Faq />;
      default:
        return null;
    }
  };
}

const mapStateToProps = (state) => {
  return {
    user: state.user.profile,
    isAdmin: state.user.isAdmin,
  };
};

export default connect(mapStateToProps, {})(AdminDashboard);
