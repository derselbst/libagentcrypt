using System.Text;

namespace LibAgentCrypt.Tests;

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
}
