package cloud

import "strings"

// Region holds the service endpoints the Handy app uses for one country/region
// (EnvironmentConfig + ServiceEndpoints in the app's region table).
type Region struct {
	Name string
	// APIBaseURL is the Retrofit base URL; every service path is appended to it.
	APIBaseURL string
	// MallAPIBaseURL serves the `mall-app-bff/*` paths.
	MallAPIBaseURL string
	// MQTTHost / MQTTURL is the EMQX broker for cloud printer control.
	MQTTHost string
	MQTTURL  string
	// IMAPIURL / IMWSURL serve the in-app messaging service.
	IMAPIURL string
	IMWSURL  string
	// HMSBaseURL is the error-code / health-management help site.
	HMSBaseURL string
	// AnalyticsBaseURL receives app telemetry (not reimplemented here).
	AnalyticsBaseURL string
}

var (
	// RegionIntl is the international production environment ("Others", US, UK and EU share it).
	RegionIntl = Region{
		Name:             "intl",
		APIBaseURL:       "https://api.bambulab.com/v1/",
		MallAPIBaseURL:   "https://ap-store-api.bambulab.com",
		MQTTHost:         "us.mqtt.bambulab.com",
		MQTTURL:          "ssl://us.mqtt.bambulab.com:8883",
		IMAPIURL:         "https://api.bambulab.com/v1/im-service/api",
		IMWSURL:          "wss://api.bambulab.com/v1/im-service/msg",
		HMSBaseURL:       "https://e.bambulab.com",
		AnalyticsBaseURL: "https://event.bblmw.com/",
	}
	// RegionChina is the mainland-China production environment (CN flavor). The app's
	// failover pool lists https://api.lunkuocorp.cn/ first and https://api.bambulab.cn/ second.
	RegionChina = Region{
		Name:             "china",
		APIBaseURL:       "https://api.lunkuocorp.cn/v1/",
		MallAPIBaseURL:   "https://ap-store-api.bambulab.com",
		MQTTHost:         "cn.mqtt.bambulab.com",
		MQTTURL:          "ssl://cn.mqtt.bambulab.com:8883",
		IMAPIURL:         "https://api.lunkuocorp.cn/v1/im-service/api",
		IMWSURL:          "wss://api.lunkuocorp.cn/v1/im-service/msg",
		HMSBaseURL:       "https://e.bambulab.cn",
		AnalyticsBaseURL: "https://event.bblmw.cn/",
	}
)

// RegionByName returns the region for "intl"/"us"/"eu"/"uk"/"others" or "china"/"cn".
func RegionByName(name string) (Region, bool) {
	switch strings.ToLower(name) {
	case "", "intl", "us", "eu", "uk", "others", "global":
		return RegionIntl, true
	case "cn", "china":
		return RegionChina, true
	}
	return Region{}, false
}
