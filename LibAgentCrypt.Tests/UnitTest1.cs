using System.Text;

namespace LibAgentCrypt.Tests;

public class Base64Tests
{
    [Fact]
    public void ToBase64_ShouldEncodeWithoutPadding()
    {
        var input = new byte[] { 1, 2, 3, 4, 5 };
        var base64 = AgentCrypt.ToBase64(input);
        
        Assert.DoesNotContain("=", base64);
        Assert.NotEmpty(base64);
    }

    [Fact]
    public void FromBase64_ShouldDecodeWithoutPadding()
    {
        var original = new byte[] { 1, 2, 3, 4, 5 };
        var base64 = AgentCrypt.ToBase64(original);
        var decoded = AgentCrypt.FromBase64(base64);
        
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void FromBase64_ShouldDecodeWithPadding()
    {
        var original = new byte[] { 1, 2, 3, 4, 5 };
        var base64 = Convert.ToBase64String(original); // With padding
        var decoded = AgentCrypt.FromBase64(base64);
        
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void Base64_RoundTrip_ShouldPreserveData()
    {
        var original = new byte[100];
        new Random(42).NextBytes(original);
        
        var base64 = AgentCrypt.ToBase64(original);
        var decoded = AgentCrypt.FromBase64(base64);
        
        Assert.Equal(original, decoded);
    }
}

public class AgentCryptVersionTests
{
    [Fact]
    public void GetVersion_ShouldReturnValidVersion()
    {
        var version = AgentCrypt.GetVersion();
        
        Assert.NotNull(version);
        Assert.NotEmpty(version);
        Assert.Matches(@"\d+\.\d+\.\d+", version);
    }
}

public class AgentCryptApiTests
{
    [Fact]
    public void Encrypt_ShouldThrowOnNullInput()
    {
        Assert.Throws<ArgumentNullException>(() => AgentCrypt.Encrypt(null!));
    }

    [Fact]
    public void Decrypt_ShouldThrowOnNullInput()
    {
        Assert.Throws<ArgumentNullException>(() => AgentCrypt.Decrypt(null!));
    }

    [Fact]
    public void Decrypt_ShouldThrowOnTooShortInput()
    {
        var shortData = new byte[10];
        Assert.Throws<InvalidDataException>(() => AgentCrypt.Decrypt(shortData));
    }

    [Fact]
    public void ToBase64_ShouldHandleEmptyArray()
    {
        var result = AgentCrypt.ToBase64(Array.Empty<byte>());
        Assert.Empty(result);
    }

    [Fact]
    public void FromBase64_ShouldHandleEmptyString()
    {
        var result = AgentCrypt.FromBase64(string.Empty);
        Assert.Empty(result);
    }
}
