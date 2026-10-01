from flask import Flask, request, jsonify
import json
from pathlib import Path


app = Flask(__name__)

ALERT_DIRECTORY = Path("data/alerts")
ALERT_DIRECTORY.mkdir(
    parents=True,
    exist_ok=True
)


@app.route("/wazuh-alert", methods=["POST"])
def wazuh_alert():

    alert = request.get_json(silent=True)

    if not alert:
        return jsonify({
            "status": "error",
            "message": "Invalid JSON"
        }), 400

    print("\n" + "=" * 60)
    print("WAZUH ALERT RECEIVED")
    print("=" * 60)

    print(json.dumps(alert, indent=4))

    output_file = (
        ALERT_DIRECTORY /
        "wazuh_alert.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            alert,
            file,
            indent=4
        )

    print("=" * 60)
    print("Alert saved to:", output_file)
    print("=" * 60)

    return jsonify({
        "status": "success",
        "message": "Wazuh alert received"
    }), 200


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
