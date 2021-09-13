import React, { Component } from "react";
import { connect } from "react-redux";
import { Skeleton } from "antd";
import { getAdminUser, updateParticipantProfile } from "../../../actions/admin";
import { getFieldData } from "../../../utils/helper";
import ProfileForm from "../../user/profile-form";

class UserEdit extends Component {
  constructor(props) {
    super(props);
    this.state = {
      avatarURL: "",
      loading: false,
    };
  }

  componentDidMount = async () => {
    this.setState({ loading: true });
    await this.props.getAdminUser(this.props.id);
    this.setState({ loading: false });
  };

  setAvatar = (url) => {
    this.setState({ avatarURL: url });
  };

  onUpdateProfile = async (profile) => {
    profile._id = this.props.id;
    await this.props.updateParticipantProfile({ profile });
    this.props.hideModal();
  };

  render = () => {
    const { admin, fieldData } = this.props;
    const { avatarURL, loading } = this.state;
    let profile = admin.participant.profile || {};
    profile.email = admin.participant.email;
    const roles = getFieldData(fieldData, "user_role");

    return (
      <div>
        <Skeleton active loading={loading} />
        <Skeleton active loading={loading} />
        {!loading && (
          <ProfileForm
            onSubmit={this.onUpdateProfile}
            profile={profile}
            setAvatar={this.setAvatar}
            avatarURL={avatarURL || profile.photo}
            roles={roles}
            fieldData={fieldData}
          />
        )}
      </div>
    );
  };
}

function mapStateToProps(state) {
  return {
    admin: state.admin,
    fieldData: state.profile.fieldData,
  };
}

export default connect(mapStateToProps, {
  updateParticipantProfile,
  getAdminUser,
})(UserEdit);
