#!/bin/bash
# Populate database with 10 ICQ test users (UINs 123400-123409) via management API.
# All profile fields are populated with realistic values. Some users have max-length fields.
#
# Usage: ./scripts/populate_icq_users.sh [API_URL]
# Default API_URL: http://127.0.0.1:8080

API="${1:-http://127.0.0.1:8080}"

# ICQ country codes: 1=USA, 44=UK, 49=Germany, 380=Ukraine, 972=Israel, 81=Japan, 55=Brazil, 61=Australia, 33=France
# ICQ language codes: 1=Arabic, 2=Bhojpuri, 3=Bulgarian, 4=Burmese, 5=Cantonese, 6=Catalan, 7=Chinese, 8=Croatian,
#   9=Czech, 10=Danish, 11=Dutch, 12=English, 13=Esperanto, 14=Estonian, 15=Farstrider, 16=Finnish, 17=French,
#   18=Gaelic, 19=German, 20=Greek, 21=Hebrew, 22=Hindi, 23=Hungarian, 24=Icelandic, 25=Indonesian, 26=Italian,
#   27=Japanese, 28=Khmer, 29=Korean, 30=Lao, 31=Latvian, 32=Lithuanian, 33=Malay, 34=Mandarin, 35=Norwegian,
#   36=Persian, 37=Polish, 38=Portuguese, 39=Romanian, 40=Russian, 41=Serbian, 42=Slovak, 43=Slovenian,
#   44=Somali, 45=Spanish, 46=Swahili, 47=Swedish, 48=Tagalog, 49=Tatar, 50=Thai, 51=Turkish, 52=Ukrainian,
#   53=Urdu, 54=Vietnamese, 55=Yiddish
# ICQ interest codes: 100=Art, 101=Cars, 102=Celebrity Fans, 103=Collections, 104=Computers, 105=Culture,
#   106=Fitness, 107=Games, 108=Hobbies, 109=ICQ-Help, 110=Internet, 111=Lifestyle, 112=Movies, 113=Music,
#   114=Outdoors, 115=Parenting, 116=Pets, 117=Religion, 118=Science, 119=Skills, 120=Sports, 121=Web Design,
#   122=Ecology, 123=News, 124=Travel, 125=Astronomy, 126=Space, 127=Clothing, 128=Parties, 129=Women,
#   130=Social Science, 131=60s, 132=70s, 133=80s, 134=50s, 135=Finance, 136=Food
# ICQ occupation codes: 1=Academic, 2=Administrative, 3=Art/Entertainment, 4=College Student, 5=Computers,
#   6=Community, 7=Education, 8=Engineering, 9=Financial Services, 10=Government, 11=High School Student,
#   12=Home, 13=ICQ-Providing Help, 14=Law, 15=Managerial, 16=Manufacturing, 17=Medical/Health,
#   18=Military, 19=Not Employed, 20=Other Services, 99=Retired
# ICQ affiliation codes (past): 200=Elementary School, 201=High School, 202=College, 203=University,
#   204=Military, 205=Past Work Place, 206=Past Organization, 207=Other
# ICQ affiliation codes (current): 300=Alumni Org, 301=Charity Org, 302=Club/Social Org, 303=Community Org,
#   304=Cultural Org, 305=Fan Clubs, 306=Fraternity/Sorority, 307=Hobbyists Org, 308=International Org,
#   309=Nature and Environment Org, 310=Professional Org, 311=Scientific/Technical Org, 312=Self Improvement,
#   313=Spiritual/Religious Org, 314=Sports Org, 315=Support Org, 316=Trade and Business Org,
#   317=Union, 318=Volunteer Org, 399=Other
# Gender: 0=not specified, 1=female, 2=male

set -e

create_user() {
    local uin="$1"
    echo "Creating user $uin..."
    curl -s -o /dev/null -w "  -> %{http_code}\n" -X POST "$API/user" \
        -H 'Content-Type: application/json' \
        -d "{\"screen_name\":\"$uin\",\"password\":\"123123\"}" || true
}

set_profile() {
    local uin="$1"
    local json="$2"
    echo "Setting profile for $uin..."
    local code
    code=$(curl -s -o /dev/stderr -w "%{http_code}" -X PUT "$API/user/$uin/icq" \
        -H 'Content-Type: application/json' \
        -d "$json" 2>/dev/null)
    if [ "$code" = "204" ]; then
        echo "  -> ok"
    else
        echo "  -> FAILED (HTTP $code)"
    fi
}

echo "=== Populating 10 ICQ users (123400-123409) ==="
echo "API: $API"
echo ""


# --- User 1: 123400 - Normal male user, USA ---
create_user 123400
set_profile 123400 '{
  "uin": 123400,
  "basic_info": {
    "nickname": "Johnny",
    "first_name": "John",
    "last_name": "Smith",
    "email": "john.smith@example.com",
    "city": "New York",
    "state": "NY",
    "phone": "+1-555-010-0100",
    "fax": "+1-555-010-0101",
    "address": "350 Maple Avenue",
    "cell_phone": "+1-555-917-0100",
    "zip": "10118",
    "country_code": 1,
    "gmt_offset": 251,
    "publish_email": true
  },
  "more_info": {
    "gender": 2,
    "homepage": "http://johnny.example.com",
    "birth_year": 1985,
    "birth_month": 3,
    "birth_day": 15,
    "lang1": 12,
    "lang2": 45,
    "lang3": 0
  },
  "work_info": {
    "company": "Pinnacle Systems",
    "department": "Engineering",
    "position": "Senior Developer",
    "occupation_code": 5,
    "address": "1 Commerce Plaza",
    "city": "New York",
    "state": "NY",
    "zip": "10007",
    "country_code": 1,
    "phone": "+1-555-020-0200",
    "fax": "+1-555-020-0201",
    "web_page": "http://pinnaclesys.example.com"
  },
  "notes": "Hey there! I am using ICQ.",
  "interests": {
    "code1": 104, "keyword1": "Programming",
    "code2": 110, "keyword2": "Web Development",
    "code3": 113, "keyword3": "Jazz Music",
    "code4": 120, "keyword4": "Basketball"
  },
  "affiliations": {
    "past_code1": 203, "past_keyword1": "Eastfield University",
    "past_code2": 205, "past_keyword2": "Orion Software",
    "past_code3": 0, "past_keyword3": "",
    "current_code1": 310, "current_keyword1": "Dev Guild",
    "current_code2": 314, "current_keyword2": "NYC Basketball League",
    "current_code3": 0, "current_keyword3": ""
  },
  "permissions": {
    "auth_required": false,
    "web_aware": true,
    "allow_spam": false
  }
}'

# --- User 2: 123401 - Female user, UK, max-length fields ---
create_user 123401
set_profile 123401 '{
  "uin": 123401,
  "basic_info": {
    "nickname": "ElizabethMaryJaneAnn",
    "first_name": "ElizabethMargaretAnneJenniferSophiaCharlotteIsabellaVictoriaAlex",
    "last_name": "Worthington-Smythe-Pemberton-Ashford-Blackwell-Montgomery-Crawfo",
    "email": "elizabeth.worthington-smythe-pemberton@longdomainname.example.co",
    "city": "London Borough of Richmond upon Thames and Surrounding Districts",
    "state": "Greater London Metropolitan Area with Extended Regional Boundari",
    "phone": "+44-555-794-6095-ext-1234567",
    "fax": "+44-555-794-6095-ext-1234567",
    "address": "221 Baker Lane, Marylebone, Westminster, Central London District",
    "cell_phone": "+44-555-770-0901-ext-1234567",
    "zip": "NW1 6XE ABCD",
    "country_code": 44,
    "gmt_offset": 0,
    "publish_email": true
  },
  "more_info": {
    "gender": 1,
    "homepage": "http://elizabeth-worthington-smythe-pemberton-ashford-blackwell-montgomery-crawford-wellington.example.co.uk",
    "birth_year": 1990,
    "birth_month": 12,
    "birth_day": 25,
    "lang1": 12,
    "lang2": 17,
    "lang3": 19
  },
  "work_info": {
    "company": "Meridian Broadcasting International Media Services Division Limi",
    "department": "Digital Transformation and Innovation Strategy Research Departme",
    "position": "Principal Research Scientist and Technical Lead for AI Initiativ",
    "occupation_code": 8,
    "address": "Broadcasting Centre Portland Place Westminster London England Un",
    "city": "London Borough of Westminster and Greater Metropolitan Area Dist",
    "state": "Greater London Metropolitan County Area with Extended Regional B",
    "zip": "W1A 1AA BCDE",
    "country_code": 44,
    "phone": "+44-555-758-0446-ext-12345",
    "fax": "+44-555-758-0446-ext-12345",
    "web_page": "http://meridian-digital-transformation-innovation-strategy-research-department-artificial-intelligence.example.co.uk"
  },
  "notes": "This is a test profile with maximum length fields to verify that ICQ clients can handle long strings properly. The notes field supports up to 450 characters. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit.",
  "interests": {
    "code1": 100, "keyword1": "Contemporary Art and Modern Sculpture Exhibition Design Curating",
    "code2": 105, "keyword2": "World Cultural Heritage Preservation and Historical Architecture",
    "code3": 118, "keyword3": "Quantum Computing Research and Theoretical Physics Applications",
    "code4": 124, "keyword4": "International Travel Photography and Adventure Tourism Planning"
  },
  "affiliations": {
    "past_code1": 203, "past_keyword1": "Westbridge University College of Computer Science and Engineerin",
    "past_code2": 202, "past_keyword2": "Kingsfield College Department of Computing and Applied Engineeri",
    "past_code3": 201, "past_keyword3": "Thornhill Academy for Advanced Mathematics and Natural Sciences",
    "current_code1": 308, "current_keyword1": "International Association for Computing Professionals UK Chapter",
    "current_code2": 311, "current_keyword2": "Royal Society for the Encouragement of Arts Manufactures Commer",
    "current_code3": 304, "current_keyword3": "Heritage Museum Friends Society and Cultural Heritage Preservati"
  },
  "permissions": {
    "auth_required": true,
    "web_aware": true,
    "allow_spam": false
  }
}'

# --- User 3: 123402 - German user, male ---
create_user 123402
set_profile 123402 '{
  "uin": 123402,
  "basic_info": {
    "nickname": "HansMueller",
    "first_name": "Hans",
    "last_name": "Mueller",
    "email": "hans.mueller@example.de",
    "city": "Berlin",
    "state": "Berlin",
    "phone": "+49-555-030-0100",
    "fax": "",
    "address": "Lindenstrasse 77",
    "cell_phone": "+49-555-170-0100",
    "zip": "10117",
    "country_code": 49,
    "gmt_offset": 1,
    "publish_email": false
  },
  "more_info": {
    "gender": 2,
    "homepage": "http://hans-mueller.example.de",
    "birth_year": 1978,
    "birth_month": 10,
    "birth_day": 3,
    "lang1": 19,
    "lang2": 12,
    "lang3": 17
  },
  "work_info": {
    "company": "Nordwerk Industries",
    "department": "Research",
    "position": "Lead Engineer",
    "occupation_code": 8,
    "address": "Industrieweg 1",
    "city": "Munich",
    "state": "Bavaria",
    "zip": "80333",
    "country_code": 49,
    "phone": "+49-555-089-0200",
    "fax": "+49-555-089-0201",
    "web_page": "http://nordwerk.example.de"
  },
  "notes": "Hallo! Ich benutze ICQ seit 1998.",
  "interests": {
    "code1": 101, "keyword1": "Automobiles",
    "code2": 107, "keyword2": "Strategy Games",
    "code3": 118, "keyword3": "Physics",
    "code4": 106, "keyword4": "Cycling"
  },
  "affiliations": {
    "past_code1": 203, "past_keyword1": "Berlin Technical University",
    "past_code2": 0, "past_keyword2": "",
    "past_code3": 0, "past_keyword3": "",
    "current_code1": 310, "current_keyword1": "VDI Engineers Association",
    "current_code2": 0, "current_keyword2": "",
    "current_code3": 0, "current_keyword3": ""
  },
  "permissions": {
    "auth_required": true,
    "web_aware": false,
    "allow_spam": false
  }
}'

# --- User 4: 123403 - Ukrainian female user ---
create_user 123403
set_profile 123403 '{
  "uin": 123403,
  "basic_info": {
    "nickname": "Oksana",
    "first_name": "Oksana",
    "last_name": "Kovalenko",
    "email": "oksana.kovalenko@example.ua",
    "city": "Kyiv",
    "state": "Kyiv",
    "phone": "+380-555-044-0100",
    "fax": "+380-555-044-0101",
    "address": "Khreshchatyk 12, apt 45",
    "cell_phone": "+380-555-067-0100",
    "zip": "01001",
    "country_code": 380,
    "gmt_offset": 2,
    "publish_email": true
  },
  "more_info": {
    "gender": 1,
    "homepage": "http://oksana.example.ua",
    "birth_year": 1992,
    "birth_month": 6,
    "birth_day": 21,
    "lang1": 52,
    "lang2": 12,
    "lang3": 17
  },
  "work_info": {
    "company": "Dnipro Digital",
    "department": "Design",
    "position": "UX Designer",
    "occupation_code": 3,
    "address": "Velyka Vasylkivska 30",
    "city": "Kyiv",
    "state": "Kyiv",
    "zip": "01004",
    "country_code": 380,
    "phone": "+380-555-044-7000",
    "fax": "",
    "web_page": "http://dniprodigital.example.ua"
  },
  "notes": "Pryvit! Looking for old ICQ friends.",
  "interests": {
    "code1": 100, "keyword1": "Painting",
    "code2": 112, "keyword2": "Art House Cinema",
    "code3": 124, "keyword3": "Travel",
    "code4": 136, "keyword4": "Cooking"
  },
  "affiliations": {
    "past_code1": 203, "past_keyword1": "Kyiv National University",
    "past_code2": 205, "past_keyword2": "Sunrise Media Group",
    "past_code3": 0, "past_keyword3": "",
    "current_code1": 304, "current_keyword1": "Kyiv Art Society",
    "current_code2": 0, "current_keyword2": "",
    "current_code3": 0, "current_keyword3": ""
  },
  "permissions": {
    "auth_required": false,
    "web_aware": true,
    "allow_spam": true
  }
}'


# --- User 5: 123404 - Israeli user, male, tech ---
create_user 123404
set_profile 123404 '{
  "uin": 123404,
  "basic_info": {
    "nickname": "Avi",
    "first_name": "Avraham",
    "last_name": "Cohen",
    "email": "avi.cohen@example.co.il",
    "city": "Tel Aviv",
    "state": "Tel Aviv",
    "phone": "+972-555-030-0100",
    "fax": "",
    "address": "Herzl Blvd 42",
    "cell_phone": "+972-555-054-0100",
    "zip": "6688312",
    "country_code": 972,
    "gmt_offset": 2,
    "publish_email": false
  },
  "more_info": {
    "gender": 2,
    "homepage": "http://avi-dev.example.co.il",
    "birth_year": 1988,
    "birth_month": 1,
    "birth_day": 8,
    "lang1": 21,
    "lang2": 12,
    "lang3": 0
  },
  "work_info": {
    "company": "ShieldNet Security",
    "department": "Security",
    "position": "CTO",
    "occupation_code": 5,
    "address": "Innovation Park 30",
    "city": "Tel Aviv",
    "state": "Tel Aviv",
    "zip": "6971009",
    "country_code": 972,
    "phone": "+972-555-030-0200",
    "fax": "+972-555-030-0201",
    "web_page": "http://shieldnet.example.co.il"
  },
  "notes": "Shalom! ICQ was invented here :)",
  "interests": {
    "code1": 104, "keyword1": "Cybersecurity",
    "code2": 118, "keyword2": "Cryptography",
    "code3": 110, "keyword3": "Startups",
    "code4": 120, "keyword4": "Football"
  },
  "affiliations": {
    "past_code1": 203, "past_keyword1": "Haifa Institute of Technology",
    "past_code2": 204, "past_keyword2": "Military Service",
    "past_code3": 205, "past_keyword3": "Firewall Systems Ltd",
    "current_code1": 310, "current_keyword1": "National Cyber Directorate",
    "current_code2": 316, "current_keyword2": "Tel Aviv Tech Hub",
    "current_code3": 0, "current_keyword3": ""
  },
  "permissions": {
    "auth_required": true,
    "web_aware": false,
    "allow_spam": false
  }
}'

# --- User 6: 123405 - Japanese female user ---
create_user 123405
set_profile 123405 '{
  "uin": 123405,
  "basic_info": {
    "nickname": "Yuki",
    "first_name": "Yuki",
    "last_name": "Tanaka",
    "email": "yuki.tanaka@example.jp",
    "city": "Tokyo",
    "state": "Tokyo",
    "phone": "+81-555-300-0100",
    "fax": "+81-555-300-0101",
    "address": "Shibuya 2-21-1",
    "cell_phone": "+81-555-900-0100",
    "zip": "150-0002",
    "country_code": 81,
    "gmt_offset": 9,
    "publish_email": true
  },
  "more_info": {
    "gender": 1,
    "homepage": "http://yuki-art.example.jp",
    "birth_year": 1995,
    "birth_month": 4,
    "birth_day": 1,
    "lang1": 27,
    "lang2": 12,
    "lang3": 0
  },
  "work_info": {
    "company": "Sakura Games",
    "department": "Game Design",
    "position": "Character Artist",
    "occupation_code": 3,
    "address": "Kamitoba 11-1",
    "city": "Kyoto",
    "state": "Kyoto",
    "zip": "601-8501",
    "country_code": 81,
    "phone": "+81-555-750-0200",
    "fax": "",
    "web_page": "http://sakuragames.example.jp"
  },
  "notes": "Konnichiwa! I love retro computing and pixel art.",
  "interests": {
    "code1": 107, "keyword1": "Retro Gaming",
    "code2": 100, "keyword2": "Pixel Art",
    "code3": 113, "keyword3": "J-Pop",
    "code4": 103, "keyword4": "Figurines"
  },
  "affiliations": {
    "past_code1": 203, "past_keyword1": "Tokyo University of the Arts",
    "past_code2": 0, "past_keyword2": "",
    "past_code3": 0, "past_keyword3": "",
    "current_code1": 305, "current_keyword1": "Retro Gaming Club Japan",
    "current_code2": 307, "current_keyword2": "Tokyo Pixel Artists",
    "current_code3": 0, "current_keyword3": ""
  },
  "permissions": {
    "auth_required": false,
    "web_aware": true,
    "allow_spam": false
  }
}'

# --- User 7: 123406 - Brazilian male, minimal work info ---
create_user 123406
set_profile 123406 '{
  "uin": 123406,
  "basic_info": {
    "nickname": "Rafa",
    "first_name": "Rafael",
    "last_name": "Santos",
    "email": "rafael.santos@example.com.br",
    "city": "Sao Paulo",
    "state": "SP",
    "phone": "+55-555-110-0100",
    "fax": "",
    "address": "Av Ipiranga 1578",
    "cell_phone": "+55-555-119-0100",
    "zip": "01310-200",
    "country_code": 55,
    "gmt_offset": 253,
    "publish_email": true
  },
  "more_info": {
    "gender": 2,
    "homepage": "http://rafa-music.example.com.br",
    "birth_year": 2000,
    "birth_month": 7,
    "birth_day": 4,
    "lang1": 38,
    "lang2": 12,
    "lang3": 45
  },
  "work_info": {
    "company": "Freelance",
    "department": "",
    "position": "Music Producer",
    "occupation_code": 3,
    "address": "",
    "city": "Sao Paulo",
    "state": "SP",
    "zip": "",
    "country_code": 55,
    "phone": "",
    "fax": "",
    "web_page": "http://beats.example.com/rafa"
  },
  "notes": "Oi! Music is life. Always looking for collabs.",
  "interests": {
    "code1": 113, "keyword1": "Electronic Music",
    "code2": 107, "keyword2": "DJ Games",
    "code3": 128, "keyword3": "Nightlife",
    "code4": 120, "keyword4": "Surfing"
  },
  "affiliations": {
    "past_code1": 202, "past_keyword1": "SP Conservatory of Music",
    "past_code2": 0, "past_keyword2": "",
    "past_code3": 0, "past_keyword3": "",
    "current_code1": 302, "current_keyword1": "SP Electronic Music Collective",
    "current_code2": 0, "current_keyword2": "",
    "current_code3": 0, "current_keyword3": ""
  },
  "permissions": {
    "auth_required": false,
    "web_aware": true,
    "allow_spam": true
  }
}'

# --- User 8: 123407 - Australian female, science ---
create_user 123407
set_profile 123407 '{
  "uin": 123407,
  "basic_info": {
    "nickname": "DrKate",
    "first_name": "Katherine",
    "last_name": "Williams",
    "email": "k.williams@example.edu.au",
    "city": "Sydney",
    "state": "NSW",
    "phone": "+61-555-200-0100",
    "fax": "+61-555-200-0101",
    "address": "42 Harbour Street",
    "cell_phone": "+61-555-400-0100",
    "zip": "2000",
    "country_code": 61,
    "gmt_offset": 10,
    "publish_email": false
  },
  "more_info": {
    "gender": 1,
    "homepage": "http://kwilliams.example.edu.au",
    "birth_year": 1982,
    "birth_month": 11,
    "birth_day": 30,
    "lang1": 12,
    "lang2": 0,
    "lang3": 0
  },
  "work_info": {
    "company": "Coral Bay University",
    "department": "Marine Biology",
    "position": "Associate Professor",
    "occupation_code": 1,
    "address": "Oceanview Campus",
    "city": "Sydney",
    "state": "NSW",
    "zip": "2006",
    "country_code": 61,
    "phone": "+61-555-935-2222",
    "fax": "+61-555-935-2223",
    "web_page": "http://coralbay.example.edu.au/bio"
  },
  "notes": "Marine biologist studying coral reef ecosystems. Always happy to chat about ocean conservation!",
  "interests": {
    "code1": 118, "keyword1": "Marine Biology",
    "code2": 122, "keyword2": "Ocean Conservation",
    "code3": 114, "keyword3": "Scuba Diving",
    "code4": 125, "keyword4": "Astronomy"
  },
  "affiliations": {
    "past_code1": 203, "past_keyword1": "Southport University",
    "past_code2": 203, "past_keyword2": "Reef Coast University",
    "past_code3": 0, "past_keyword3": "",
    "current_code1": 311, "current_keyword1": "Australian Marine Sciences Assoc",
    "current_code2": 309, "current_keyword2": "Reef Conservation Foundation",
    "current_code3": 310, "current_keyword3": "Royal Society of NSW"
  },
  "permissions": {
    "auth_required": true,
    "web_aware": true,
    "allow_spam": false
  }
}'


# --- User 9: 123408 - French male, finance ---
create_user 123408
set_profile 123408 '{
  "uin": 123408,
  "basic_info": {
    "nickname": "Pierre",
    "first_name": "Pierre",
    "last_name": "Dubois",
    "email": "pierre.dubois@example.fr",
    "city": "Paris",
    "state": "Ile-de-France",
    "phone": "+33-555-014-0100",
    "fax": "+33-555-014-0101",
    "address": "15 Rue de la Paix",
    "cell_phone": "+33-555-067-0100",
    "zip": "75002",
    "country_code": 33,
    "gmt_offset": 1,
    "publish_email": true
  },
  "more_info": {
    "gender": 2,
    "homepage": "http://pierre-finance.example.fr",
    "birth_year": 1980,
    "birth_month": 5,
    "birth_day": 14,
    "lang1": 17,
    "lang2": 12,
    "lang3": 19
  },
  "work_info": {
    "company": "Lumiere Capital",
    "department": "Investment Banking",
    "position": "Portfolio Manager",
    "occupation_code": 9,
    "address": "8 Place Vendome",
    "city": "Paris",
    "state": "Ile-de-France",
    "zip": "75001",
    "country_code": 33,
    "phone": "+33-555-014-0200",
    "fax": "+33-555-014-0201",
    "web_page": "http://lumierecapital.example.fr"
  },
  "notes": "Bonjour! Interested in fintech and wine tasting. Always up for a good conversation.",
  "interests": {
    "code1": 135, "keyword1": "Finance",
    "code2": 136, "keyword2": "Wine and Cuisine",
    "code3": 105, "keyword3": "French Culture",
    "code4": 124, "keyword4": "European Travel"
  },
  "affiliations": {
    "past_code1": 203, "past_keyword1": "Sorbonne Business School",
    "past_code2": 205, "past_keyword2": "Alpine Investments",
    "past_code3": 0, "past_keyword3": "",
    "current_code1": 310, "current_keyword1": "European Finance Association",
    "current_code2": 316, "current_keyword2": "Paris Fintech Forum",
    "current_code3": 0, "current_keyword3": ""
  },
  "permissions": {
    "auth_required": true,
    "web_aware": true,
    "allow_spam": false
  }
}'

# --- User 10: 123409 - Ukrainian male, student ---
create_user 123409
set_profile 123409 '{
  "uin": 123409,
  "basic_info": {
    "nickname": "Taras",
    "first_name": "Taras",
    "last_name": "Bondarenko",
    "email": "taras.bondarenko@example.ua",
    "city": "Lviv",
    "state": "Lviv Oblast",
    "phone": "+380-555-032-0100",
    "fax": "",
    "address": "Svobody Ave 28",
    "cell_phone": "+380-555-097-0100",
    "zip": "79000",
    "country_code": 380,
    "gmt_offset": 2,
    "publish_email": true
  },
  "more_info": {
    "gender": 2,
    "homepage": "http://taras-dev.example.ua",
    "birth_year": 2001,
    "birth_month": 8,
    "birth_day": 24,
    "lang1": 52,
    "lang2": 12,
    "lang3": 37
  },
  "work_info": {
    "company": "",
    "department": "",
    "position": "Student",
    "occupation_code": 4,
    "address": "Universytetska 1",
    "city": "Lviv",
    "state": "Lviv Oblast",
    "zip": "79000",
    "country_code": 380,
    "phone": "",
    "fax": "",
    "web_page": "http://lvivpoly.example.ua"
  },
  "notes": "CS student. Open source enthusiast. Love retro tech and old protocols!",
  "interests": {
    "code1": 104, "keyword1": "Open Source",
    "code2": 107, "keyword2": "Retro Computing",
    "code3": 110, "keyword3": "Linux",
    "code4": 113, "keyword4": "Electronic Music"
  },
  "affiliations": {
    "past_code1": 201, "past_keyword1": "Lviv Lyceum No 1",
    "past_code2": 0, "past_keyword2": "",
    "past_code3": 0, "past_keyword3": "",
    "current_code1": 302, "current_keyword1": "Lviv Open Source Community",
    "current_code2": 307, "current_keyword2": "Retro Computing Club",
    "current_code3": 0, "current_keyword3": ""
  },
  "permissions": {
    "auth_required": false,
    "web_aware": true,
    "allow_spam": false
  }
}'

echo ""
echo "=== Done ==="
