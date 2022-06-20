package cz.fit.bp.fw_author.controller;

import cz.fit.bp.fw_author.service.UpdateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileNotFoundException;
import java.io.IOException;

@RestController
@RequestMapping("upload")
public class UpdateController {

    @Autowired
    private UpdateService updateService;

    @PostMapping
    public ResponseEntity<?> uploadFirmware(@RequestParam Integer id, @RequestParam String deviceType, @RequestParam String firmwarePath, @RequestParam String fwName){
        try {
            updateService.uploadFirmwareImage(firmwarePath, fwName, id, deviceType);
        }catch (FileNotFoundException e){
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        } catch (IOException e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.UNPROCESSABLE_ENTITY);
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }



}
