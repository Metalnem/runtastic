package api

var (
	types = toMap([]ActivityType{
		{1, "Running", "running"},
		{2, "Nordic Walking", "nordicwalking"},
		{3, "Cycling", "cycling"},
		{4, "Mountain Biking", "mountainbiking"},
		{5, "Other", "other"},
		{6, "Skating", "skating"},
		{7, "Hiking", "hiking"},
		{8, "Cross Country Skiing", "crosscountryskiing"},
		{9, "Skiing", "skiing"},
		{10, "Snow Boarding", "snowboarding"},
		{11, "Motorbiking", "motorbiking"},
		{14, "Running (Treadmill)", "treadmill"},
		{15, "Cycling (Ergometer)", "ergometer"},
		{16, "Elliptical", "elliptical"},
		{17, "Rowing", "rowing"},
		{18, "Swimming", "swimming"},
		{19, "Walking", "strolling"},
		{20, "Riding", "riding"},
		{21, "Golfing", "golfing"},
		{22, "Race Cycling", "racecycling"},
		{23, "Tennis", "tennis"},
		{24, "Badminton", "badminton"},
		{25, "Squash", "squash"},
		{26, "Yoga", "yoga"},
		{27, "Aerobics", "aerobics"},
		{28, "Martial Arts", "martial_arts"},
		{29, "Sailing", "sailing"},
		{30, "Windsurfing", "windsurfing"},
		{31, "Pilates", "pilates"},
		{32, "Climbing", "climbing"},
		{34, "Strength Training", "strength_training"},
		{35, "Volleyball", "volleyball"},
		{36, "Handbike", "handbike"},
		{38, "Soccer", "soccer"},
		{42, "Surfing", "surfing"},
		{43, "Kite Surfing", "kite_surfing"},
		{44, "Kayaking", "kayaking"},
		{45, "Basketball", "basketball"},
		{46, "Spinning", "spinning"},
		{47, "Paragliding", "paragliding"},
		{48, "Wake Boarding", "wakeboarding"},
		{50, "Diving", "diving"},
		{51, "Table Tennis", "table_tennis"},
		{52, "Handball", "handball"},
		{53, "Back Country Skiing", "back_country_skiing"},
		{54, "Ice Skating", "ice_skating"},
		{55, "Sledding", "sledding"},
		{58, "Curling", "curling"},
		{60, "Biathlon", "biathlon"},
		{67, "American Football", "american_football"},
		{68, "Baseball", "baseball"},
		{69, "Crossfit", "crossfit"},
		{70, "Dancing", "dancing"},
		{71, "Ice Hockey", "ice_hockey"},
		{72, "Skateboarding", "skateboarding"},
		{73, "Zumba", "zumba"},
		{74, "Gymnastics", "gymnastics"},
		{75, "Rugby", "rugby"},
		{76, "Standup Paddling", "standup_paddling"},
	})
)

// ActivityType represents type of activity (e.g., running and cycling).
type ActivityType struct {
	ID          int64
	DisplayName string
	ExportName  string
}

func toMap(types []ActivityType) map[int64]ActivityType {
	m := make(map[int64]ActivityType)

	for _, t := range types {
		m[t.ID] = t
	}

	return m
}
