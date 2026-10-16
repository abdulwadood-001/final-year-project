# Diagrams (SDS v2.1)

| File | Shows |
|---|---|
| `ad1_device_state` … `ad9_ml_dataset` | Activity diagrams of SDS Section 4.2, one per module workflow (M1–M8) |
| `deployment_architecture_70.png` | Deployment architecture at the 70% milestone (SDS Figure 2) |
| `er_diagram_70.png` | ER diagram of the v0.7 schema (SDS Figure 18) |

Regenerate an activity diagram (PlantUML 1.2024+, Java):

```bash
java -DPLANTUML_LIMIT_SIZE=8192 -jar plantuml.jar -tpng ad3_malware_capture.puml
```

`make_arch.py` and `make_er.py` write the architecture and ER diagrams as SVG
(`python make_arch.py arch.svg`); open the SVG in a browser or convert it to PNG.
