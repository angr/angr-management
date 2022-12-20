import random

ADJECTIVES = [
"abandoned",
"able",
"absolute",
"adorable",
"adventurous",
"academic",
"acceptable",
"acclaimed",
"accomplished",
"accurate",
"aching",
"acidic",
"acrobatic",
"active",
"actual",
"adept",
"admirable",
"admired",
"adolescent",
"adorable",
"adored",
"advanced",
"afraid",
"affectionate",
"aged",
"aggravating",
"aggressive",
"agile",
"agitated",
"agonizing",
"agreeable",
"ajar",
"alarmed",
"alarming",
"alert",
"alienated",
"alive",
"all",
"altruistic",
"amazing",
"ambitious",
"ample",
"amused",
"amusing",
"anchored",
"ancient",
"angelic",
"angry",
"anguished",
"animated",
"annual",
"another",
"antique",
"anxious",
"any",
"apprehensive",
"appropriate",
"apt",
"arctic",
"arid",
"aromatic",
"artistic",
"ashamed",
"assured",
"astonishing",
"athletic",
"attached",
"attentive",
"attractive",
"austere",
"authentic",
"authorized",
"automatic",
"avaricious",
"average",
"aware",
"awesome",
"awful",
"awkward",
"babyish",
"bad",
"back",
"baggy",
"bare",
"barren",
"basic",
"beautiful",
"belated",
"beloved",
"beneficial",
"better",
"best",
"bewitched",
"big",
"big-hearted",
"biodegradable",
"bite-sized",
"bitter",
"black",
"black-and-white",
"bland",
"blank",
"blaring",
"bleak",
"blind",
"blissful",
"blond",
"blue",
"blushing",
"bogus",
"boiling",
"bold",
"bony",
"boring",
"bossy",
"both",
"bouncy",
"bountiful",
"bowed",
"brave",
"breakable",
"brief",
"bright",
"brilliant",
"brisk",
"broken",
"bronze",
"brown",
"bruised",
"bubbly",
"bulky",
"bumpy",
"buoyant",
"burdensome",
"burly",
"bustling",
"busy",
"buttery",
"buzzing",
"calculating",
"calm",
"candid",
"canine",
"capital",
"carefree",
"careful",
"careless",
"caring",
"cautious",
"cavernous",
"celebrated",
"charming",
"cheap",
"cheerful",
"cheery",
"chief",
"chilly",
"chubby",
"circular",
"classic",
"clean",
"clear",
"clear-cut",
"clever",
"close",
"closed",
"cloudy",
"clueless",
"clumsy",
"cluttered",
"coarse",
"cold",
"colorful",
"colorless",
"colossal",
"comfortable",
"common",
"compassionate",
"competent",
"complete",
"complex",
"complicated",
"composed",
"concerned",
"concrete",
"confused",
"conscious",
"considerate",
"constant",
"content",
"conventional",
"cooked",
"cool",
"cooperative",
"coordinated",
"corny",
"corrupt",
"costly",
"courageous",
"courteous",
"crafty",
"crazy",
"creamy",
"creative",
"creepy",
"criminal",
"crisp",
"critical",
"crooked",
"crowded",
"cruel",
"crushing",
"cuddly",
"cultivated",
"cultured",
"cumbersome",
"curly",
"curvy",
"cute",
"cylindrical",
"damaged",
"damp",
"dangerous",
"dapper",
"daring",
"darling",
"dark",
"dazzling",
"dead",
"deadly",
"deafening",
"dear",
"dearest",
"decent",
"decimal",
"decisive",
"deep",
"defenseless",
"defensive",
"defiant",
"deficient",
"definite",
"definitive",
"delayed",
"delectable",
"delicious",
"delightful",
"delirious",
"demanding",
"dense",
"dental",
"dependable",
"dependent",
"descriptive",
"deserted",
"detailed",
"determined",
"devoted",
"different",
"difficult",
"digital",
"diligent",
"dim",
"dimpled",
"dimwitted",
"direct",
"disastrous",
"discrete",
"disfigured",
"disgusting",
"disloyal",
"dismal",
"distant",
"downright",
"dreary",
"dirty",
"disguised",
"dishonest",
"dismal",
"distant",
"distinct",
"distorted",
"dizzy",
"dopey",
"doting",
"double",
"downright",
"drab",
"drafty",
"dramatic",
"dreary",
"droopy",
"dry",
"dual",
"dull",
"dutiful",
"E",
"each",
"eager",
"earnest",
"early",
"easy",
"easy-going",
"ecstatic",
"edible",
"educated",
"elaborate",
"elastic",
"elated",
"elderly",
"electric",
"elegant",
"elementary",
"elliptical",
"embarrassed",
"embellished",
"eminent",
"emotional",
"empty",
"enchanted",
"enchanting",
"energetic",
"enlightened",
"enormous",
"enraged",
"entire",
"envious",
"equal",
"equatorial",
"essential",
"esteemed",
"ethical",
"euphoric",
"even",
"evergreen",
"everlasting",
"every",
"evil",
"exalted",
"excellent",
"exemplary",
"exhausted",
"excitable",
"excited",
"exciting",
"exotic",
"expensive",
"experienced",
"expert",
"extraneous",
"extroverted",
"extra-large",
"extra-small",
"F",
"fabulous",
"failing",
"faint",
"fair",
"faithful",
"fake",
"false",
"familiar",
"famous",
"fancy",
"fantastic",
"far",
"faraway",
"far-flung",
"far-off",
"fast",
"fat",
"fatal",
"fatherly",
"favorable",
"favorite",
"fearful",
"fearless",
"feisty",
"feline",
"female",
"feminine",
"few",
"fickle",
"filthy",
"fine",
"finished",
"firm",
"first",
"firsthand",
"fitting",
"fixed",
"flaky",
"flamboyant",
"flashy",
"flat",
"flawed",
"flawless",
"flickering",
"flimsy",
"flippant",
"flowery",
"fluffy",
"fluid",
"flustered",
"focused",
"fond",
"foolhardy",
"foolish",
"forceful",
"forked",
"formal",
"forsaken",
"forthright",
"fortunate",
"fragrant",
"frail",
"frank",
"frayed",
"free",
"French",
"fresh",
"frequent",
"friendly",
"frightened",
"frightening",
"frigid",
"frilly",
"frizzy",
"frivolous",
"front",
"frosty",
"frozen",
"frugal",
"fruitful",
"full",
"fumbling",
"functional",
"funny",
"fussy",
"fuzzy",
"gargantuan",
"gaseous",
"general",
"generous",
"gentle",
"genuine",
"giant",
"giddy",
"gigantic",
"gifted",
"giving",
"glamorous",
"glaring",
"glass",
"gleaming",
"gleeful",
"glistening",
"glittering",
"gloomy",
"glorious",
"glossy",
"glum",
"golden",
"good",
"good-natured",
"gorgeous",
"graceful",
"gracious",
"grand",
"grandiose",
"granular",
"grateful",
"grave",
"gray",
"great",
"greedy",
"green",
"gregarious",
"grim",
"grimy",
"gripping",
"grizzled",
"gross",
"grotesque",
"grouchy",
"grounded",
"growing",
"growling",
"grown",
"grubby",
"gruesome",
"grumpy",
"guilty",
"gullible",
"gummy",
"hairy",
"half",
"handmade",
"handsome",
"handy",
"happy",
"happy-go-lucky",
"hard",
"hard-to-find",
"harmful",
"harmless",
"harmonious",
"harsh",
"hasty",
"hateful",
"haunting",
"healthy",
"heartfelt",
"hearty",
"heavenly",
"heavy",
"hefty",
"helpful",
"helpless",
"hidden",
"hideous",
"high",
"high-level",
"hilarious",
"hoarse",
"hollow",
"homely",
"honest",
"honorable",
"honored",
"hopeful",
"horrible",
"hospitable",
"hot",
"huge",
"humble",
"humiliating",
"humming",
"humongous",
"hungry",
"hurtful",
"husky",
"icky",
"icy",
"ideal",
"idealistic",
"identical",
"idle",
"idiotic",
"idolized",
"ignorant",
"ill",
"illegal",
"ill-fated",
"ill-informed",
"illiterate",
"illustrious",
"imaginary",
"imaginative",
"immaculate",
"immaterial",
"immediate",
"immense",
"impassioned",
"impeccable",
"impartial",
"imperfect",
"imperturbable",
"impish",
"impolite",
"important",
"impossible",
"impractical",
"impressionable",
"impressive",
"improbable",
"impure",
"inborn",
"incomparable",
"incompatible",
"incomplete",
"inconsequential",
"incredible",
"indelible",
"inexperienced",
"indolent",
"infamous",
"infantile",
"infatuated",
"inferior",
"infinite",
"informal",
"innocent",
"insecure",
"insidious",
"insignificant",
"insistent",
"instructive",
"insubstantial",
"intelligent",
"intent",
"intentional",
"interesting",
"internal",
"international",
"intrepid",
"ironclad",
"irresponsible",
"irritating",
"itchy",
"jaded",
"jagged",
"jam-packed",
"jaunty",
"jealous",
"jittery",
"joint",
"jolly",
"jovial",
"joyful",
"joyous",
"jubilant",
"judicious",
"juicy",
"jumbo",
"junior",
"jumpy",
"juvenile",
"kaleidoscopic",
"keen",
"key",
"kind",
"kindhearted",
"kindly",
"klutzy",
"knobby",
"knotty",
"knowledgeable",
"knowing",
"known",
"kooky",
"kosher",
"lame",
"lanky",
"large",
"last",
"lasting",
"late",
"lavish",
"lawful",
"lazy",
"leading",
"lean",
"leafy",
"left",
"legal",
"legitimate",
"light",
"lighthearted",
"likable",
"likely",
"limited",
"limp",
"limping",
"linear",
"lined",
"liquid",
"little",
"live",
"lively",
"livid",
"loathsome",
"lone",
"lonely",
"long",
"long-term",
"loose",
"lopsided",
"lost",
"loud",
"lovable",
"lovely",
"loving",
"low",
"loyal",
"lucky",
"lumbering",
"luminous",
"lumpy",
"lustrous",
"luxurious",
"mad",
"made-up",
"magnificent",
"majestic",
"major",
"male",
"mammoth",
"married",
"marvelous",
"masculine",
"massive",
"mature",
"meager",
"mealy",
"mean",
"measly",
"meaty",
"medical",
"mediocre",
"medium",
"meek",
"mellow",
"melodic",
"memorable",
"menacing",
"merry",
"messy",
"metallic",
"mild",
"milky",
"mindless",
"miniature",
"minor",
"minty",
"miserable",
"miserly",
"misguided",
"misty",
"mixed",
"modern",
"modest",
"moist",
"monstrous",
"monthly",
"monumental",
"moral",
"mortified",
"motherly",
"motionless",
"mountainous",
"muddy",
"muffled",
"multicolored",
"mundane",
"murky",
"mushy",
"musty",
"muted",
"mysterious",
"naive",
"narrow",
"nasty",
"natural",
"naughty",
"nautical",
"near",
"neat",
"necessary",
"needy",
"negative",
"neglected",
"negligible",
"neighboring",
"nervous",
"new",
"next",
"nice",
"nifty",
"nimble",
"nippy",
"nocturnal",
"noisy",
"nonstop",
"normal",
"notable",
"noted",
"noteworthy",
"novel",
"noxious",
"numb",
"nutritious",
"nutty",
"obedient",
"obese",
"oblong",
"oily",
"oblong",
"obvious",
"occasional",
"odd",
"oddball",
"offbeat",
"offensive",
"official",
"old",
"old-fashioned",
"only",
"open",
"optimal",
"optimistic",
"opulent",
"orange",
"orderly",
"organic",
"ornate",
"ornery",
"ordinary",
"original",
"other",
"our",
"outlying",
"outgoing",
"outlandish",
"outrageous",
"outstanding",
"oval",
"overcooked",
"overdue",
"overjoyed",
"overlooked",
"palatable",
"pale",
"paltry",
"parallel",
"parched",
"partial",
"passionate",
"past",
"pastel",
"peaceful",
"peppery",
"perfect",
"perfumed",
"periodic",
"perky",
"personal",
"pertinent",
"pesky",
"pessimistic",
"petty",
"phony",
"physical",
"piercing",
"pink",
"pitiful",
"plain",
"plaintive",
"plastic",
"playful",
"pleasant",
"pleased",
"pleasing",
"plump",
"plush",
"polished",
"polite",
"political",
"pointed",
"pointless",
"poised",
"poor",
"popular",
"portly",
"posh",
"positive",
"possible",
"potable",
"powerful",
"powerless",
"practical",
"precious",
"present",
"prestigious",
"pretty",
"precious",
"previous",
"pricey",
"prickly",
"primary",
"prime",
"pristine",
"private",
"prize",
"probable",
"productive",
"profitable",
"profuse",
"proper",
"proud",
"prudent",
"punctual",
"pungent",
"puny",
"pure",
"purple",
"pushy",
"putrid",
"puzzled",
"puzzling",
"quaint",
"qualified",
"quarrelsome",
"quarterly",
"queasy",
"querulous",
"questionable",
"quick",
"quick-witted",
"quiet",
"quintessential",
"quirky",
"quixotic",
"quizzical",
"radiant",
"ragged",
"rapid",
"rare",
"rash",
"raw",
"recent",
"reckless",
"rectangular",
"ready",
"real",
"realistic",
"reasonable",
"red",
"reflecting",
"regal",
"regular",
"reliable",
"relieved",
"remarkable",
"remorseful",
"remote",
"repentant",
"required",
"respectful",
"responsible",
"repulsive",
"revolving",
"rewarding",
"rich",
"rigid",
"right",
"ringed",
"ripe",
"roasted",
"robust",
"rosy",
"rotating",
"rotten",
"rough",
"round",
"rowdy",
"royal",
"rubbery",
"rundown",
"ruddy",
"rude",
"runny",
"rural",
"rusty",
"sad",
"safe",
"salty",
"same",
"sandy",
"sane",
"sarcastic",
"sardonic",
"satisfied",
"scaly",
"scarce",
"scared",
"scary",
"scented",
"scholarly",
"scientific",
"scornful",
"scratchy",
"scrawny",
"second",
"secondary",
"second-hand",
"secret",
"self-assured",
"self-reliant",
"selfish",
"sentimental",
"separate",
"serene",
"serious",
"serpentine",
"several",
"severe",
"shabby",
"shadowy",
"shady",
"shallow",
"shameful",
"shameless",
"sharp",
"shimmering",
"shiny",
"shocked",
"shocking",
"shoddy",
"short",
"short-term",
"showy",
"shrill",
"shy",
"sick",
"silent",
"silky",
"silly",
"silver",
"similar",
"simple",
"simplistic",
"sinful",
"single",
"sizzling",
"skeletal",
"skinny",
"sleepy",
"slight",
"slim",
"slimy",
"slippery",
"slow",
"slushy",
"small",
"smart",
"smoggy",
"smooth",
"smug",
"snappy",
"snarling",
"sneaky",
"sniveling",
"snoopy",
"sociable",
"soft",
"soggy",
"solid",
"somber",
"some",
"spherical",
"sophisticated",
"sore",
"sorrowful",
"soulful",
"soupy",
"sour",
"Spanish",
"sparkling",
"sparse",
"specific",
"spectacular",
"speedy",
"spicy",
"spiffy",
"spirited",
"spiteful",
"splendid",
"spotless",
"spotted",
"spry",
"square",
"squeaky",
"squiggly",
"stable",
"staid",
"stained",
"stale",
"standard",
"starchy",
"stark",
"starry",
"steep",
"sticky",
"stiff",
"stimulating",
"stingy",
"stormy",
"straight",
"strange",
"steel",
"strict",
"strident",
"striking",
"striped",
"strong",
"studious",
"stunning",
"stupendous",
"stupid",
"sturdy",
"stylish",
"subdued",
"submissive",
"substantial",
"subtle",
"suburban",
"sudden",
"sugary",
"sunny",
"super",
"superb",
"superficial",
"superior",
"supportive",
"sure-footed",
"surprised",
"suspicious",
"svelte",
"sweaty",
"sweet",
"sweltering",
"swift",
"sympathetic",
"tall",
"talkative",
"tame",
"tan",
"tangible",
"tart",
"tasty",
"tattered",
"taut",
"tedious",
"teeming",
"tempting",
"tender",
"tense",
"tepid",
"terrible",
"terrific",
"testy",
"thankful",
"that",
"these",
"thick",
"thin",
"third",
"thirsty",
"this",
"thorough",
"thorny",
"those",
"thoughtful",
"threadbare",
"thrifty",
"thunderous",
"tidy",
"tight",
"timely",
"tinted",
"tiny",
"tired",
"torn",
"total",
"tough",
"traumatic",
"treasured",
"tremendous",
"tragic",
"trained",
"tremendous",
"triangular",
"tricky",
"trifling",
"trim",
"trivial",
"troubled",
"true",
"trusting",
"trustworthy",
"trusty",
"truthful",
"tubby",
"turbulent",
"twin",
"ugly",
"ultimate",
"unacceptable",
"unaware",
"uncomfortable",
"uncommon",
"unconscious",
"understated",
"unequaled",
"uneven",
"unfinished",
"unfit",
"unfolded",
"unfortunate",
"unhappy",
"unhealthy",
"uniform",
"unimportant",
"unique",
"united",
"unkempt",
"unknown",
"unlawful",
"unlined",
"unlucky",
"unnatural",
"unpleasant",
"unrealistic",
"unripe",
"unruly",
"unselfish",
"unsightly",
"unsteady",
"unsung",
"untidy",
"untimely",
"untried",
"untrue",
"unused",
"unusual",
"unwelcome",
"unwieldy",
"unwilling",
"unwitting",
"unwritten",
"upbeat",
"upright",
"upset",
"urban",
"usable",
"used",
"useful",
"useless",
"utilized",
"utter",
"vacant",
"vague",
"vain",
"valid",
"valuable",
"vapid",
"variable",
"vast",
"velvety",
"venerated",
"vengeful",
"verifiable",
"vibrant",
"vicious",
"victorious",
"vigilant",
"vigorous",
"villainous",
"violet",
"violent",
"virtual",
"virtuous",
"visible",
"vital",
"vivacious",
"vivid",
"voluminous",
"wan",
"warlike",
"warm",
"warmhearted",
"warped",
"wary",
"wasteful",
"watchful",
"waterlogged",
"watery",
"wavy",
"wealthy",
"weak",
"weary",
"webbed",
"wee",
"weekly",
"weepy",
"weighty",
"weird",
"welcome",
"well-documented",
"well-groomed",
"well-informed",
"well-lit",
"well-made",
"well-off",
"well-to-do",
"well-worn",
"wet",
"which",
"whimsical",
"whirlwind",
"whispered",
"white",
"whole",
"whopping",
"wicked",
"wide",
"wide-eyed",
"wiggly",
"wild",
"willing",
"wilted",
"winding",
"windy",
"winged",
"wiry",
"wise",
"witty",
"wobbly",
"woeful",
"wonderful",
"wooden",
"woozy",
"wordy",
"worldly",
"worn",
"worried",
"worrisome",
"worse",
"worst",
"worthless",
"worthwhile",
"worthy",
"wrathful",
"wretched",
"writhing",
"wrong",
"wry",
"yawning",
"yearly",
"yellow",
"yellowish",
"young",
"youthful",
"yummy",
"zany",
"zealous",
"zesty",
"zigzag",
]

ANIMALS = [
"aardwolf",
"admiral",
"adouri",
"african black crake",
"african buffalo",
"african bush squirrel",
"african clawless otter",
"african darter",
"african elephant",
"african fish eagle",
"african ground squirrel",
"african jacana",
"african lion",
"african lynx",
"african pied wagtail",
"african polecat",
"african porcupine",
"african red-eyed bulbul",
"african skink",
"african snake",
"african wild cat",
"african wild dog",
"agama lizard",
"agile wallaby",
"agouti",
"albatross",
"alligator",
"alpaca",
"amazon parrot",
"american alligator",
"american badger",
"american beaver",
"american bighorn sheep",
"american bison",
"american black bear",
"american buffalo",
"american crow",
"american marten",
"american racer",
"american virginia opossum",
"american woodcock",
"anaconda",
"andean goose",
"ant",
"anteater",
"antechinus",
"antelope",
"antelope ground squirrel",
"arboral spiny rat",
"arctic fox",
"arctic ground squirrel",
"arctic hare",
"arctic lemming",
"arctic tern",
"argalis",
"armadillo",
"asian elephant",
"asian false vampire bat",
"asian foreset tortoise",
"asian lion",
"asian openbill",
"asian red fox",
"asian water buffalo",
"asian water dragon",
"asiatic jackal",
"asiatic wild ass",
"ass",
"australian brush turkey",
"australian magpie",
"australian masked owl",
"australian pelican",
"australian sea lion",
"australian spiny anteater",
"avocet",
"baboon",
"badger",
"bahama pintail",
"bald eagle",
"baleen whale",
"banded mongoose",
"bandicoot",
"barasingha deer",
"barbet",
"bare-faced go away bird",
"barking gecko",
"barrows goldeneye",
"bat",
"bat-eared fox",
"bateleur eagle",
"bear",
"beaver",
"bee-eater",
"beisa oryx",
"bengal vulture",
"bent-toed gecko",
"bettong",
"bird",
"bison",
"black and white colobus",
"black-backed jackal",
"black-backed magpie",
"black bear",
"blackbird",
"blackbuck",
"black-capped capuchin",
"black-capped chickadee",
"black-cheeked waxbill",
"black-collared barbet",
"black-crowned crane",
"black-crowned night heron",
"black curlew",
"black-eyed bulbul",
"black-faced kangaroo",
"black-footed ferret",
"black-fronted bulbul",
"blackish oystercatcher",
"black kite",
"black-necked stork",
"black rhinoceros",
"blacksmith plover",
"black spider monkey",
"black swan",
"black-tailed deer",
"black-tailed prairie dog",
"black-tailed tree creeper",
"black-throated butcher bird",
"black-throated cardinal",
"black vulture",
"black-winged stilt",
"bleeding heart monkey",
"blesbok",
"bleu",
"blue and gold macaw",
"blue and yellow macaw",
"blue-breasted cordon bleu",
"blue catfish",
"blue crane",
"blue duck",
"blue-faced booby",
"blue-footed booby",
"blue fox",
"blue peacock",
"blue racer",
"blue shark",
"blue-tongued lizard",
"blue-tongued skink",
"blue waxbill",
"blue wildebeest",
"boa",
"boar",
"boat-billed heron",
"bobcat",
"bohor reedbuck",
"bonnet macaque",
"bontebok",
"booby",
"bottle-nose dolphin",
"boubou",
"brazilian otter",
"brazilian tapir",
"brindled gnu",
"brocket",
"brolga crane",
"brown and yellow marshbird",
"brown antechinus",
"brown brocket",
"brown capuchin",
"brown hyena",
"brown lemur",
"brown pelican",
"brush-tailed bettong",
"brush-tailed phascogale",
"brush-tailed rat kangaroo",
"buffalo",
"bulbul",
"bunting",
"burmese black mountain tortoise",
"burmese brown mountain tortoise",
"burrowing owl",
"bushbaby",
"bushbuck",
"bush dog",
"bushpig",
"bustard",
"butterfly",
"buttermilk snake",
"caiman",
"california sea lion",
"camel",
"campo flicker",
"canada goose",
"canadian river otter",
"canadian tiger swallowtail butterfly",
"cape barren goose",
"cape clawless otter",
"cape cobra",
"cape fox",
"cape raven",
"cape starling",
"cape white-eye",
"cape wild cat",
"capuchin",
"capybara",
"caracal",
"caracara",
"cardinal",
"caribou",
"carmine bee-eater",
"carpet python",
"carpet snake",
"cat",
"catfish",
"cattle egret",
"cereopsis goose",
"chacma baboon",
"chameleon",
"cheetah",
"chestnut weaver",
"chickadee",
"chilean flamingo",
"chimpanzee",
"chipmunk",
"chital",
"chuckwalla",
"civet",
"civet",
"civet cat",
"cliffchat",
"coatimundi",
"cobra",
"cockatoo",
"collared lemming",
"collared lizard",
"collared peccary",
"colobus",
"columbian rainbow boa",
"comb duck",
"common boubou shrike",
"common brushtail possum",
"common dolphin",
"common duiker",
"common eland",
"common genet",
"common goldeneye",
"common green iguana",
"common grenadier",
"common langur",
"common long-nosed armadillo",
"common melba finch",
"common mynah",
"common nighthawk",
"common palm civet",
"common pheasant",
"common raccoon",
"common rhea",
"common ringtail",
"common seal",
"common shelduck",
"common turkey",
"common wallaroo",
"common waterbuck",
"common wolf",
"common wombat",
"common zebra",
"common zorro",
"constrictor",
"coot",
"coqui francolin",
"coqui partridge",
"corella",
"cormorant",
"cottonmouth",
"cougar",
"cow",
"coyote",
"crab",
"crab-eating fox",
"crab-eating raccoon",
"crake",
"crane",
"creeper",
"crested barbet",
"crested bunting",
"crested porcupine",
"crested screamer",
"crimson-breasted shrike",
"crocodile",
"crow",
"crowned eagle",
"crowned hawk-eagle",
"crown of thorns starfish",
"cuis",
"curlew",
"currasow",
"curve-billed thrasher",
"dabchick",
"dama wallaby",
"dark-winged trumpeter",
"darter",
"darwin ground finch",
"dassie",
"deer",
"defassa waterbuck",
"desert kangaroo rat",
"desert spiny lizard",
"desert tortoise",
"devil",
"dik",
"dingo",
"dog",
"dolphin",
"dove",
"downy woodpecker",
"dragon",
"dragonfly",
"dromedary camel",
"drongo",
"duck",
"duiker",
"dunnart",
"dusky gull",
"dusky rattlesnake",
"eagle",
"eagle owl",
"eastern boa constrictor",
"eastern box turtle",
"eastern cottontail rabbit",
"eastern diamondback rattlesnake",
"eastern dwarf mongoose",
"eastern fox squirrel",
"eastern grey kangaroo",
"eastern indigo snake",
"eastern quoll",
"eastern white pelican",
"echidna",
"egret",
"egyptian cobra",
"egyptian goose",
"egyptian viper",
"egyptian vulture",
"eland",
"elegant crested tinamou",
"elephant",
"eleven-banded armadillo",
"elk",
"emerald green tree boa",
"emerald-spotted wood dove",
"emu",
"eurasian badger",
"eurasian beaver",
"eurasian hoopoe",
"eurasian red squirrel",
"european badger",
"european beaver",
"european red squirrel",
"european shelduck",
"european spoonbill",
"european stork",
"european wild cat",
"euro wallaby",
"fairy penguin",
"falcon",
"fat-tailed dunnart",
"feathertail glider",
"feral rock pigeon",
"ferret",
"ferruginous hawk",
"field flicker",
"finch",
"fisher",
"flamingo",
"flicker",
"flightless cormorant",
"flycatcher",
"flying fox",
"fork-tailed drongo",
"four-horned antelope",
"four-spotted skimmer",
"four-striped grass mouse",
"fowl",
"fox",
"francolin",
"frilled dragon",
"frilled lizard",
"fringe-eared oryx",
"frog",
"frogmouth",
"galah",
"galapagos albatross",
"galapagos dove",
"galapagos hawk",
"galapagos mockingbird",
"galapagos penguin",
"galapagos sea lion",
"galapagos tortoise",
"gaur",
"gazelle",
"gazer",
"gecko",
"gelada baboon",
"gemsbok",
"genet",
"genoveva",
"gerbil",
"gerenuk",
"giant anteater",
"giant armadillo",
"giant girdled lizard",
"giant heron",
"giant otter",
"gila monster",
"giraffe",
"glider",
"glossy ibis",
"glossy starling",
"gnu",
"goanna lizard",
"goat",
"godwit",
"golden brush-tailed possum",
"golden eagle",
"goldeneye",
"golden jackal",
"golden-mantled ground squirrel",
"goliath heron",
"gonolek",
"goose",
"gorilla",
"gray duiker",
"gray heron",
"gray langur",
"gray rhea",
"great cormorant",
"great egret",
"greater adjutant stork",
"greater blue-eared starling",
"greater flamingo",
"greater kudu",
"greater rhea",
"greater roadrunner",
"greater sage grouse",
"great horned owl",
"great kiskadee",
"great skua",
"great white pelican",
"grebe",
"green-backed heron",
"green heron",
"green vine snake",
"green-winged macaw",
"green-winged trumpeter",
"grenadier",
"grey-footed squirrel",
"grey fox",
"grey heron",
"greylag goose",
"grey lourie",
"grey mouse lemur",
"grey phalarope",
"griffon vulture",
"grison",
"grizzly bear",
"groundhog",
"ground legaan",
"ground monitor",
"grouse",
"guanaco",
"guerza",
"gull",
"gulls",
"hanuman langur",
"harbor seal",
"hare",
"hartebeest",
"hawk",
"hawk-eagle",
"hawk-headed parrot",
"hedgehog",
"helmeted guinea fowl",
"hen",
"heron",
"herring gull",
"hippopotamus",
"hoary marmot",
"honey badger",
"hoopoe",
"hornbill",
"horned lark",
"horned puffin",
"horned rattlesnake",
"hottentot teal",
"house crow",
"house sparrow",
"hudsonian godwit",
"hummingbird",
"huron",
"hyena",
"hyrax",
"ibex",
"ibis",
"iguana",
"impala",
"indian giant squirrel",
"indian jackal",
"indian leopard",
"indian mynah",
"indian peacock",
"indian porcupine",
"indian red admiral",
"indian star tortoise",
"indian tree pie",
"insect",
"jabiru stork",
"jacana",
"jackal",
"jackrabbit",
"jaeger",
"jaguar",
"jaguarundi",
"japanese macaque",
"javanese cormorant",
"javan gold-spotted mongoose",
"jungle cat",
"jungle kangaroo",
"kaffir cat",
"kafue flats lechwe",
"kalahari scrub robin",
"kangaroo",
"kelp gull",
"killer whale",
"king cormorant",
"kingfisher",
"king vulture",
"kinkajou",
"kiskadee",
"kite",
"klipspringer",
"knob-nosed goose",
"koala",
"komodo dragon",
"kongoni",
"kookaburra",
"kori bustard",
"kudu",
"land iguana",
"langur",
"lappet-faced vulture",
"lapwing",
"large cormorant",
"large-eared bushbaby",
"lark",
"laughing dove",
"laughing kookaburra",
"lava gull",
"least chipmunk",
"lechwe",
"legaan",
"lemming",
"lemur",
"leopard",
"lesser double-collared sunbird",
"lesser flamingo",
"lesser masked weaver",
"lesser mouse lemur",
"lilac-breasted roller",
"lily trotter",
"lion",
"little blue penguin",
"little brown bat",
"little brown dove",
"little cormorant",
"little grebe",
"little heron",
"lizard",
"llama",
"long-billed cockatoo",
"long-billed corella",
"long-crested hawk eagle",
"long-finned pilot whale",
"long-necked turtle",
"long-nosed bandicoot",
"long-tailed jaeger",
"long-tailed skua",
"long-tailed spotted cat",
"lorikeet",
"loris",
"lory",
"lourie",
"lynx",
"macaque",
"macaw",
"madagascar fruit bat",
"madagascar hawk owl",
"magellanic penguin",
"magistrate black colobus",
"magnificent frigate bird",
"magpie",
"malabar squirrel",
"malachite kingfisher",
"malagasy ground boa",
"malay squirrel",
"mallard",
"malleefowl",
"manatee",
"mandras tree shrew",
"mara",
"marabou stork",
"margay",
"marine iguana",
"marmot",
"marshbird",
"marten",
"masked booby",
"meerkat",
"mexican beaded lizard",
"mexican boa",
"mexican wolf",
"mississippi alligator",
"moccasin",
"mockingbird",
"mocking cliffchat",
"mongoose",
"monitor",
"monitor lizard",
"monkey",
"monster",
"moorhen",
"moose",
"mouflon",
"mountain duck",
"mountain goat",
"mountain lion",
"mourning collared dove",
"mouse",
"mudskipper",
"mule deer",
"musk ox",
"mynah",
"native cat",
"nelson ground squirrel",
"neotropic cormorant",
"netted rock dragon",
"nighthawk",
"nile crocodile",
"nilgai",
"nine-banded armadillo",
"north american beaver",
"north american porcupine",
"north american red fox",
"north american river otter",
"northern elephant seal",
"northern fur seal",
"northern phalarope",
"nubian bee-eater",
"numbat",
"nutcracker",
"nuthatch",
"nyala",
"ocelot",
"old world fruit bat",
"olive baboon",
"onager",
"openbill",
"openbill stork",
"opossum",
"orca",
"oribi",
"oriental short-clawed otter",
"oriental white-backed vulture",
"ornate rock dragon",
"oryx",
"osprey",
"ostrich",
"otter",
"ovenbird",
"owl",
"ox",
"oystercatcher",
"paca",
"pacific gull",
"paddy heron",
"pademelon",
"painted stork",
"pale-throated three-toed sloth",
"pale white-eye",
"palm squirrel",
"pampa gray fox",
"paradoxure",
"parakeet",
"parrot",
"partridge",
"peacock",
"peccary",
"pelican",
"penguin",
"peregrine falcon",
"phalarope",
"phascogale",
"pheasant",
"pie",
"pied avocet",
"pied butcher bird",
"pied cormorant",
"pied crow",
"pied kingfisher",
"pigeon",
"pig-tailed macaque",
"pine siskin",
"pine snake",
"pine squirrel",
"pintail",
"plains zebra",
"platypus",
"plover",
"pocket gopher",
"polar bear",
"polecat",
"porcupine",
"possum",
"potoroo",
"prairie falcon",
"praying mantis",
"prehensile-tailed porcupine",
"pronghorn",
"puffin",
"puku",
"puma",
"puna ibis",
"purple grenadier",
"purple moorhen",
"pygmy possum",
"python",
"quail",
"quoll",
"rabbit",
"raccoon",
"raccoon dog",
"racer",
"racer snake",
"radiated tortoise",
"rainbow lory",
"rat",
"rattlesnake",
"raven",
"red and blue macaw",
"red-billed buffalo weaver",
"red-billed hornbill",
"red-billed toucan",
"red-billed tropic bird",
"red-breasted cockatoo",
"red-breasted nuthatch",
"red brocket",
"red-capped cardinal",
"red-cheeked cordon bleu",
"red deer",
"red hartebeest",
"red-headed woodpecker",
"red howler monkey",
"red kangaroo",
"red-knobbed coot",
"red lava crab",
"red-legged pademelon",
"red meerkat",
"red-necked phalarope",
"red-necked wallaby",
"red phalarope",
"red sheep",
"red-shouldered glossy starling",
"red squirrel",
"red-tailed cockatoo",
"red-tailed hawk",
"red-tailed phascogale",
"red-tailed wambenger",
"red-winged blackbird",
"red-winged hawk",
"reedbuck",
"reindeer",
"rhea",
"rhesus macaque",
"rhesus monkey",
"rhinoceros",
"ring dove",
"ring-necked pheasant",
"ringtail",
"ringtail",
"ringtail cat",
"ring-tailed coatimundi",
"ring-tailed gecko",
"ring-tailed lemur",
"ring-tailed possum",
"river wallaby",
"roadrunner",
"roan antelope",
"robin",
"rock dove",
"roe deer",
"roller",
"roseate cockatoo",
"roseat flamingo",
"rose-ringed parakeet",
"royal tern",
"rufous-collared sparrow",
"rufous tree pie",
"russian dragonfly",
"sable antelope",
"sacred ibis",
"saddle-billed stork",
"sage grouse",
"sage hen",
"sally lightfoot crab",
"salmon",
"salmon pink bird eater tarantula",
"sambar",
"sandgrouse",
"sandhill crane",
"sandpiper",
"sarus crane",
"savanna baboon",
"savanna fox",
"savannah deer",
"scaly-breasted lorikeet",
"scarlet macaw",
"scottish highland cow",
"screamer",
"sea birds",
"seal",
"secretary bird",
"serval",
"seven-banded armadillo",
"shark",
"sheathbill",
"sheep",
"shelduck",
"short-beaked echidna",
"short-nosed bandicoot",
"shrew",
"shrike",
"sidewinder",
"sifaka",
"silver-backed fox",
"silver-backed jackal",
"silver gull",
"siskin",
"skimmer",
"skink",
"skua",
"skunk",
"slender-billed cockatoo",
"slender loris",
"sloth",
"sloth bear",
"small-clawed otter",
"small indian mongoose",
"small-spotted genet",
"small-toothed palm civet",
"snake",
"snake-necked turtle",
"snow goose",
"snowy egret",
"snowy owl",
"snowy sheathbill",
"sociable weaver",
"sockeye salmon",
"south african hedgehog",
"south american meadowlark",
"south american puma",
"south american sea lion",
"southern black-backed gull",
"southern boubou",
"southern brown bandicoot",
"southern elephant seal",
"southern ground hornbill",
"southern hairy-nosed wombat",
"southern lapwing",
"southern right whale",
"southern screamer",
"southern sea lion",
"southern tamandua",
"southern white-crowned shrike",
"sparrow",
"spectacled caiman",
"spider",
"spoonbill",
"sportive lemur",
"spotted deer",
"spotted hyena",
"spotted-tailed quoll",
"spotted wood sandpiper",
"springbok",
"springbuck",
"springhare",
"spurfowl",
"spur-winged goose",
"square-lipped rhinoceros",
"squirrel",
"squirrel glider",
"stanley bustard",
"stanley crane",
"starfish",
"starling",
"steenbok",
"steenbuck",
"steller sea lion",
"stick insect",
"stilt",
"stone sheep",
"stork",
"striated heron",
"striped dolphin",
"striped hyena",
"striped skunk",
"sugar glider",
"sulfur-crested cockatoo",
"sunbird",
"sungazer",
"sun gazer",
"superb starling",
"suricate",
"swallow",
"swallow-tail gull",
"swamp deer",
"swan",
"tailless tenrec",
"tamandua",
"tammar wallaby",
"tapir",
"tarantula",
"tasmanian devil",
"tawny eagle",
"tawny frogmouth",
"tayra",
"teal",
"tenrec",
"tern",
"thirteen-lined squirrel",
"thrasher",
"three-banded plover",
"tiger",
"tiger cat",
"tiger snake",
"timber wolf",
"tinamou",
"toddy cat",
"tokay gecko",
"topi",
"tortoise",
"toucan",
"tree porcupine",
"tropical buckeye butterfly",
"trotter",
"trumpeter",
"trumpeter swan",
"tsessebe",
"turaco",
"turkey",
"turkey vulture",
"turtle",
"two-banded monitor",
"two-toed sloth",
"two-toed tree sloth",
"tyrant flycatcher",
"uinta ground squirrel",
"urial",
"vervet monkey",
"vicuna",
"vine snake",
"violet-crested turaco",
"violet-eared waxbill",
"viper",
"vulture",
"wagtail",
"wallaby",
"wallaroo",
"wambenger",
"wapiti",
"warthog",
"waterbuck",
"water legaan",
"water moccasin",
"water monitor",
"wattled crane",
"waved albatross",
"waxbill",
"weaver",
"weeper capuchin",
"western bearded dragon",
"western grey kangaroo",
"western lowland gorilla",
"western palm tanager",
"western patch-nosed snake",
"western pygmy possum",
"western spotted skunk",
"whale",
"whip-tailed wallaby",
"white-bellied sea eagle",
"white-browed owl",
"white-browed sparrow weaver",
"white-cheeked pintail",
"white-eye",
"white-faced tree rat",
"white-faced whistling duck",
"white-fronted bee-eater",
"white-fronted capuchin",
"white-headed vulture",
"white-lipped peccary",
"white-mantled colobus",
"white-necked raven",
"white-necked stork",
"white-nosed coatimundi",
"white rhinoceros",
"white-rumped vulture",
"white spoonbill",
"white stork",
"white-tailed deer",
"white-tailed jackrabbit",
"white-throated kingfisher",
"white-throated monitor",
"white-throated robin",
"white-throated toucan",
"white-winged black tern",
"white-winged dove",
"white-winged tern",
"wild boar",
"wildebeest",
"wild turkey",
"wild water buffalo",
"wolf",
"wolf spider",
"wombat",
"woodchuck",
"woodcock",
"woodpecker",
"wood pigeon",
"woodrat",
"woolly-necked stork",
"worm snake",
"woylie",
"yak",
"yellow baboon",
"yellow-bellied marmot",
"yellow-billed hornbill",
"yellow-billed stork",
"yellow-brown sungazer",
"yellow-crowned night heron",
"yellow-headed caracara",
"yellow mongoose",
"yellow-necked spurfowl",
"yellow-rumped siskin",
"yellow-throated sandgrouse",
"zebra",
"zorilla",
"zorro",
]

class NameGenerator:

    @staticmethod
    def random_name():

        global ADJECTIVES, ANIMALS

        return "{} {}".format(random.choice(ADJECTIVES), random.choice(ANIMALS))
