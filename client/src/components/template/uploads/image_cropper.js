import React, { useState } from "react";
import Cropper from "react-easy-crop";
import { getCroppedImg } from "./crop_image";

const ImageCropper = ({ getBlob, inputImg }) => {
  const [crop, setCrop] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [cropSize, setCropSize] = useState({width: 0, height: 0});

  /* onCropComplete() will occur each time the user modifies the cropped area, 
    which isn't ideal. A better implementation would be getting the blob 
    only when the user hits the submit button, but this works for now  */
  const onCropComplete = async (_, croppedAreaPixels) => {
    const croppedImage = await getCroppedImg(inputImg, croppedAreaPixels);
    getBlob(croppedImage);
  };

  const onMediaLoaded = (data) => {
    const size = Math.min(data.height, data.width)
    setCropSize({width: size, height: size})
  }

  return (
    /* need to have a parent with `position: relative` 
    to prevent cropper taking up whole page */
    <div className="cropper">
      <Cropper
        image={inputImg}
        crop={crop}
        zoom={zoom}
        cropSize={cropSize}
        aspect={1}
        onCropChange={setCrop}
        onCropComplete={onCropComplete}
        onZoomChange={setZoom}
        onMediaLoaded={onMediaLoaded}
      />
    </div>
  );
};

export default ImageCropper;
