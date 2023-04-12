from discord import SyncWebhook

webhook = SyncWebhook.from_url("https://discord.com/api/webhooks/1095713865955803276/ry-mECqTt_QpLvkywO_uYM5CbDeCdYNKhJIpBbuO-VDewEyv1e17M18QMoHUOBdurmuM")
webhook.send("Hello World")