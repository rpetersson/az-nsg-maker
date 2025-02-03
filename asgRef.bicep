// Create a Network Security Group (NSG)
resource nsg 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
  properties: {
    securityRules: [
      {
        name: 'Allow-ASG-Inbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'  // Change to required port (e.g., 443 for HTTPS)
          sourceAddressPrefix: ''  // Not needed when using ASG
          sourceApplicationSecurityGroups: [
            {
              id: asg.id
            }
          ]
          destinationApplicationSecurityGroups: [
            {
              id: asg.id
            }
          ]
        }
      }
    ]
  }
}


