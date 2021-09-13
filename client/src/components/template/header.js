import React, { Component } from "react";
import { connect } from "react-redux";
import {
  Collapse,
  Navbar,
  NavbarToggler,
  Nav,
  NavItem,
  UncontrolledDropdown,
  DropdownToggle,
  DropdownMenu,
  DropdownItem,
} from "reactstrap";
import { Avatar, Badge } from "antd";
import { BellOutlined, MailOutlined } from "@ant-design/icons";
import { Link } from "react-router-dom";
import sampleUrl from "../../assets/images/user-avatar.png";

class HeaderTemplate extends Component {
  constructor(props) {
    super(props);
    this.state = {
      isOpen: false,
    };
  }

  toggle = () => {
    this.setState({ isOpen: !this.state.isOpen });
  };

  render = () => {
    const { authenticated, currentUser, message, notification, isAdmin } =
      this.props;
    const { isOpen } = this.state;
    return (
      <React.Fragment>
        <div className={`main-nav ${isAdmin && "admin-nav"}`}>
          <Navbar className="container-nav" expand="md" light>
            <Link className="navbar-brand" to="/">
              <img
                src={require("../../assets/images/INDIElogo.png")}
                height="35"
                alt="logo"
                className="mt-2"
              />
            </Link>
            <NavbarToggler onClick={this.toggle} />
            <Collapse isOpen={isOpen} navbar>
              <Nav className="mr-auto" navbar>
                {authenticated && (
                  <NavItem>
                    <Link className="nav-link" to="/user-dashboard">
                      Dashboard
                    </Link>
                  </NavItem>
                )}
                {authenticated && isAdmin && (
                  <NavItem>
                    <Link className="nav-link" to="/admin">
                      Admin
                    </Link>
                  </NavItem>
                )}
              </Nav>

              <Nav navbar>
                {authenticated && (
                  <NavItem>
                    {/* <Link className="nav-link" to="/message"> */}
                    <Link className="nav-link" to="#">
                      <div
                        className="mr-2"
                        style={{
                          fontSize: 21,
                          color: "white",
                        }}
                      >
                        <Badge count={message.unread}>
                          <MailOutlined />
                        </Badge>
                      </div>
                    </Link>
                  </NavItem>
                )}
                {authenticated && (
                  <NavItem>
                    {/* <Link className="nav-link" to="/notification"> */}
                    <Link className="nav-link" to="#">
                      <div
                        className="mr-2"
                        style={{
                          fontSize: 21,
                          color: "white",
                        }}
                      >
                        <Badge count={notification.unread}>
                          <BellOutlined />
                        </Badge>
                      </div>
                    </Link>
                  </NavItem>
                )}
                {authenticated && (
                  <UncontrolledDropdown nav inNavbar>
                    <DropdownToggle nav caret>
                      {currentUser.profile && (
                        <React.Fragment>
                          <Avatar
                            src={currentUser.profile.photo || sampleUrl}
                          />{" "}
                          &nbsp;
                          {`${currentUser.profile.first_name} ${currentUser.profile.last_name}`}
                        </React.Fragment>
                      )}
                    </DropdownToggle>
                    <DropdownMenu right>
                      {/* <DropdownItem>
                        <Link className="nav-link" to="/profile">
                          Profile
                        </Link>
                      </DropdownItem> */}
                      {/* <DropdownItem divider /> */}
                      <DropdownItem>
                        <Link className="nav-link" to="/logout">
                          Logout
                        </Link>
                      </DropdownItem>
                    </DropdownMenu>
                  </UncontrolledDropdown>
                )}
                {/* {!authenticated && (
                  <React.Fragment>
                    <NavItem>
                      <Link className="nav-link" to="/login">
                        Login
                      </Link>
                    </NavItem>
                    <NavItem>
                      <Link className="nav-link" to="/register">
                        Register
                      </Link>
                    </NavItem>
                  </React.Fragment>
                )} */}
              </Nav>
            </Collapse>
          </Navbar>
        </div>
      </React.Fragment>
    );
  };
}

function mapStateToProps(state) {
  return {
    authenticated: state.auth.authenticated,
    currentUser: state.user.profile,
    isAdmin: state.user.isAdmin,
    message: state.message,
    notification: state.notification,
    fieldData: state.profile.fieldData,
  };
}

export default connect(mapStateToProps, {})(HeaderTemplate);
