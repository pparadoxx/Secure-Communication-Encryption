/*

* NAME: Secure Communication Encryption
*
* AUTHOR: paradox
*
* VERSION: 2.5
*
* GITHUB: https://github.com/pparadoxx/Secure-Communication-Encryption
*
* DESCRIPTION: A secure way to encrypt and decrypt data.

*/
local G = table.Copy(_G)

-- Local Table
local sce = {}

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
        str[k] = G.string.char(v) 
    end

    return table.concat(str)
end

return sce 
