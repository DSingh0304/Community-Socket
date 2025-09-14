import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
  },
  googleId: {
    type: String,
  },
  profileImage: {
    type: String,
    default: 'https://i.pinimg.com/736x/57/00/c0/5700c04197ee9a4372a35ef16eb78f4e.jpg',
  },
  firstProfile:{type: Boolean, default: false},
  phone: {
    type: String,
    required: true,
    unique: true,
  },
  wishlist: [
    {
      cityName: { type: String, required: true },
      parentRef: { type: mongoose.Schema.Types.ObjectId, required: true },
      onModel: {
        type: String,
        required: true,
        enum: [
          'Accommodation',
          'Activity',
          'Food',
          'HiddenGem',
          'NearbySpot',
          'Place',
          'Shop',
        ],
      },
    },
  ],
  isPremium: {
    type: String,
    enum: ['FREE', 'A', 'B'],
    default: 'FREE',
  },
  premiumStartDate: {
    type: Date,
    default: Date.now,
  },
  premiumExpiryDate: {
    type: Date,
    default: null, // means "infinite / no expiry"
  },
  referralCode: {
    type: String,
    unique: true,
    sparse: true,
  },
  referredBy: {
    type: String,
  },
contributionPoints: {
  type: Number,
  default: 0,
},
monthlyPoints: {
  type: Number,
  default: 0,
},
pointsMonth: {
  type: Date,
  default: Date.now,
},

  referralCount: {
    type: Number,
    default: 0,
  },
  signupDate: {
    type: Date,
    default: Date.now,
  },
  lastActive: {
    type: Date,
    default: Date.now,
  },
  resetToken: String,
  resetTokenExpiry: Date,
});

// ✅ Compound index to make wishlist items unique per user
userSchema.index(
  { _id: 1, "wishlist.parentRef": 1, "wishlist.onModel": 1 },
  { unique: true, sparse: true }
);

const User = mongoose.models.User || mongoose.model('User', userSchema);
export default User;
