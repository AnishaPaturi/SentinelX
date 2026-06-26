package com.scanner.controller;

import com.scanner.service.ThreatIntelService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ThreatIntelController {

    @Autowired
    private ThreatIntelService threatIntelService;

    @GetMapping("/intel")
    public Map<String, Object> queryIpThreat(@RequestParam String ip) {
        return threatIntelService.getIpDetails(ip);
    }
}
