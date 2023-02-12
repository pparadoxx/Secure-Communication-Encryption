/*

* NAME: Secure Communication Encryption
*
* AUTHOR: paradox
*
* VERSION: 3.0
*
* GITHUB: https://github.com/pparadoxx/Secure-Communication-Encryption
*
* DESCRIPTION: A secure way to encrypt and decrypt data.

*/
local G = table.Copy(_G)

-- Table
sce = {}

-- Key Generator 
function sce.Key(length)
    if !length then length = 64 end 

    local str = ""

    for i = 1, length do 
        str = str .. G.string.char(G.math.random(97,122))
    end

    return str 
end

-- Hash
function sce.Hash(str, desiredLength)
    local sha = G.util.SHA256(str)

    desiredLength = G.tostring(desiredLength) // ???

    if #sha < 256 then 
        sha = G.string.rep(sha, 4, "")
    end

    if sha >= desiredLength then return sha end 

    return G.string.rep(sha, G.math.ceil(desiredLength/#sha))
end

-- Table Hash
function sce.HashTable(tbl)
    if !tbl || !G.istable(tbl) then return end 

    local str = ""

    for k,v in G.pairs(tbl) do
        if G.isfunction(v) then 
            local gi = G.debug.getinfo( v )

            str = str .. G.util.MD5(G.util.TypeToString(gi.linedefined .. " " .. gi.short_src))
        elseif (G.isstring(v) || G.isnumber(v)) then 
             str = str .. G.util.MD5(v)
        end
    end 

    return G.util.SHA256(str)
end

-- To ASCII
function sce.ToASCII(tbl)
    for k,v in G.ipairs(tbl) do 
        if !G.isstring(v) then continue end 

        tbl[k] = G.string.byte(v)
    end

    return tbl 
end

-- Encrypt 
function sce.Encrypt(str,key)
    key = sce.ToASCII(G.string.ToTable(sce.Hash(key, #str)))
    str = sce.ToASCII(G.string.ToTable(str))

    // MATH \\
    for k,v in G.ipairs(str) do 
        local ke = key[k]

        str[k] = v + ke
    end

    // XOR \\
    for k,v in G.ipairs(str) do 
        local ke = key[k]

        str[k] = G.bit.bxor(v,ke)
    end

    // SWAP & ROLL \\
    for k,v in G.ipairs(str) do 
        local ke = key[k]

        str[k] = G.bit.bswap(G.bit.rol(v,ke))
    end

    // REBUILD \\
    str = G.table.concat(str, " ")

    return G.util.Base64Encode(str) 
end 

-- Decrypt
function sce.Decrypt(str,key)
    if !str || !key then return end 

    str = G.string.Split(G.util.Base64Decode(str), " ")
    key = sce.ToASCII(G.string.ToTable(sce.Hash(key, #str)))

    // SHIFT & ROLL \\
    for k,v in G.ipairs(str) do 
        local ke = key[k]

        str[k] = G.bit.ror(G.bit.bswap(v),ke)
    end

    // XOR \\
    for k,v in G.ipairs(str) do 
        local ke = key[k]

        str[k] = G.bit.bxor(v,ke)
    end

    // MATH \\
    for k,v in G.ipairs(str) do 
        local ke = key[k]

        str[k] = (v-ke)
    end

    // REBUILD \\
    for k,v in G.ipairs(str) do    
        local valid,success = G.pcall(G.string.char, v)

        if valid then
            str[k] = success
        else
            return nil 
        end 
    end

    return table.concat(str)
end
