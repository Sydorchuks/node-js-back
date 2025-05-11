module.exports = {
    accessTokenSecret: process.env.JWT_SECRET || 'myAccess',
    refreshTokenSecret: 'myRefreshTokenSecret'
}