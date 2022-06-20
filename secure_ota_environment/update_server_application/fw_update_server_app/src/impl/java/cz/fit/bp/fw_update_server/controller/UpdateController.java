package cz.fit.bp.fw_update_server.controller;


import cz.fit.bp.fw_update_server.entity.FirmwareImageWrapper;
import cz.fit.bp.fw_update_server.service.UpdateService;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;

@RestController
public class UpdateController {

    @Autowired
    private UpdateService updateService;

    private static Logger logger = LoggerFactory.getLogger(UpdateController.class);

    @GetMapping(path = "/update/newest/manifest")
    public ResponseEntity<?> getNewestFirmwareManifest(HttpServletResponse response, @RequestParam String deviceType) {
        try {
            logger.info("Newest firmware manifest supply START!");
            InputStream resStream;
            FirmwareImageWrapper fiw = updateService.getNewestFirmwareManifestStream(deviceType);
            HttpHeaders httpHeaders = new HttpHeaders();
            resStream = fiw.getInputStream();
            httpHeaders.add(HttpHeaders.CONTENT_LENGTH, Long.toString(fiw.getFirmwareImageData().getManifestLength()));
            IOUtils.copy(resStream, response.getOutputStream());
            response.flushBuffer();
            logger.info("Newest firmware manifest supply SUCCESS!");
            return ResponseEntity.ok().headers(httpHeaders).build();
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Newest firmware manifest supply FAILED!");
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping(path = "/update/newest/binary")
    public ResponseEntity<?> getNewestFirmwareBinary(HttpServletResponse response, @RequestParam String deviceType) {
        try {
            logger.info("Newest firmware binary supply START!");
            InputStream resStream;
            FirmwareImageWrapper fiw = updateService.getNewestFirmwareBinaryStream(deviceType);
            HttpHeaders httpHeaders = new HttpHeaders();
            resStream = fiw.getInputStream();
            httpHeaders.add(HttpHeaders.CONTENT_LENGTH, Long.toString(fiw.getFirmwareImageData().getFirmwareLength()));
            IOUtils.copy(resStream, response.getOutputStream());
            response.flushBuffer();
            logger.info("Newest firmware binary supply SUCCESS!");
            return ResponseEntity.ok().headers(httpHeaders).build();
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("Newest firmware binary supply FAILED!");
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }


    @RequestMapping(value = "/uploadFile", method = RequestMethod.POST)
    public String submit(@RequestParam("manifestFile") MultipartFile manifestFile, @RequestParam("firmwareFile") MultipartFile firmwareFile, ModelMap modelMap, @RequestParam Integer id, @RequestParam String deviceType, @RequestParam String fwName) throws IOException {
        logger.info("Firmware Author authenticated.");
        logger.info("Receiving firmware image START.");
        modelMap.addAttribute("file", manifestFile);
        updateService.storeFirmwareImage(manifestFile, firmwareFile, id, deviceType, fwName);
        logger.info("Receiving firmware image SUCCESS.");
        return "OK";
    }

}
