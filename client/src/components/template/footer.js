import React from "react";
import { Link } from "react-router-dom";

class Footer extends React.Component {
  render() {
    return (
      <div className="footer_block">
        <Link to="">
          <span className="mr-3">Sparxs Studio</span>
        </Link>
      </div>
    );
  }
}

export default Footer;
